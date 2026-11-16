import SecurityEvent from '../models/SecurityEvent.js';

// Never store passwords that appear inline in a query
const redact = (q) => String(q || '').replace(/(password\s*:\s*)"[^"]*"/gi, '$1"***"');

export function logEvent({ ip, query, score, decision, attackType }) {
  SecurityEvent.create({
    ip,
    attackType,
    riskScore: score,
    decision,
    snippet: redact(query).slice(0, 300),
  }).catch((e) => console.error('security log failed:', e.message));
}
