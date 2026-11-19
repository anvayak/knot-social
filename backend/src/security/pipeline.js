import { config } from './config.js';
import { analyzeQuery } from './queryAnalyzer.js';
import { evaluate } from './riskEngine.js';
import { hit, resetLimits } from './rateLimiter.js';
import { isBlocked, addStrike, normalizeIp, resetBlocks } from './blocklist.js';
import { logEvent } from './logger.js';
import { scanPayload } from './payloadScanner.js';
import { isAdminConsoleRequest } from './adminBypass.js';

const isProd = process.env.NODE_ENV === 'production';
const ADMIN_POLL_FIELDS = new Set(['securityStats', 'securityEvents', 'blockedIps']);
const lastBlockedLog = new Map(); // ip -> ms, so a flood doesn't spam the log

function extractQuery(req) {
  if (req.method === 'POST' && req.body && !Array.isArray(req.body)) {
    return typeof req.body.query === 'string' ? req.body.query : null;
  }
  if (req.method === 'GET') return typeof req.query?.query === 'string' ? req.query.query : null;
  return null;
}

function reject(res, status, code, message, extra = {}) {
  return res.status(status).json({ errors: [{ message, extensions: { code, ...extra } }] });
}

// Runs before Apollo on /graphql. Cheapest checks first.
export function securityPipeline(req, res, next) {
  const ip = normalizeIp(req.ip);
  const query = extractQuery(req);

  // 0. Verified admin using the console: never lock the admin out of their own dashboard
  if (isAdminConsoleRequest(req, query)) return next();

  // 1. IP block-list
  const blocked = isBlocked(ip);
  if (blocked) {
    const now = Date.now();
    if (now - (lastBlockedLog.get(ip) || 0) > 10_000) {
      lastBlockedLog.set(ip, now);
      logEvent({ ip, query: '', score: 100, decision: 'BLOCK', attackType: 'blocked_ip' });
    }
    return reject(res, 403, 'IP_BLOCKED', 'Your IP is temporarily blocked', {
      retryAfterSeconds: Math.ceil((blocked.until - now) / 1000),
    });
  }

  const extra = [];
  let analysis = null;

  // 2. Global rate limit (if exceeded we skip parsing: no CPU spent on a flood)
  const global = hit(`g:${ip}`, config.rate.global);
  if (global.exceeded) {
    extra.push({ type: 'rate_limit', points: 75, detail: `${global.count} requests/min > ${global.limit}` });
  } else if (Array.isArray(req.body)) {
    extra.push({ type: 'batching', points: 75, detail: 'batched requests are not allowed' });
  } else if (query) {
    if (query.length > config.maxQueryLength) {
      extra.push({ type: 'oversized_query', points: 75, detail: `${query.length} chars > ${config.maxQueryLength}` });
    } else {
      // 3. Static query analysis
      analysis = analyzeQuery(query);
      // Payload scanner: looks for SQLi, NoSQLi, XSS, SSRF and command injection in the values
      const variables = req.method === 'POST' ? req.body?.variables : req.query?.variables;
      extra.push(...scanPayload(analysis.malformed ? [query] : analysis.strings, variables));
      // 4. Stricter limit for login/signup (brute force). Aliases count once each.
      if (analysis.authOps > 0) {
        const auth = hit(`a:${ip}`, config.rate.auth, analysis.authOps);
        if (auth.exceeded) {
          extra.push({ type: 'auth_rate_limit', points: 75, detail: `${auth.count} login/signup attempts/min > ${auth.limit}` });
        }
      }
    }
  }

  // Plain page loads (e.g. the Sandbox landing page) carry no query: nothing to judge
  if (!query && !extra.length) return next();

  // 5. Risk score and decision
  const verdict = evaluate(analysis, extra);
  // The admin dashboard polls every few seconds; don't fill the log with those
  const adminPoll = analysis?.rootFields?.length > 0 && analysis.rootFields.every((f) => ADMIN_POLL_FIELDS.has(f));
  if (!(adminPoll && verdict.decision === 'ALLOW')) logEvent({ ip, query, ...verdict });

  if (verdict.decision === 'BLOCK') {
    const ipBlocked = addStrike(ip, verdict.attackType);
    const isRate = verdict.findings.some((f) => f.type.includes('rate_limit'));
    if (isRate) res.set('Retry-After', '60');
    return reject(res, isRate ? 429 : 403, 'SECURITY_BLOCKED',
      isRate ? 'Too many requests' : 'Request blocked by security policy', {
        riskScore: verdict.score,
        ipBlocked,
        // Detailed reasons only in development: they would help an attacker in production
        ...(isProd ? {} : { reasons: verdict.findings.map((f) => `${f.type}: ${f.detail}`) }),
      });
  }

  res.set('X-Risk-Score', String(verdict.score));
  res.set('X-Risk-Decision', verdict.decision);
  next();
}

export function resetSecurityState() {
  resetBlocks();
  resetLimits();
  lastBlockedLog.clear();
}