import { config } from './config.js';

const isProd = process.env.NODE_ENV === 'production';
const MAX_INTROSPECTION_DEPTH = 20; // the standard Sandbox query is ~15 deep

// Turns analysis results into findings (each worth some risk points), a total
// score (0-100) and a decision. Day 3 adds the payload scanner's findings here.
//
// Hard limits (depth, cost...) are worth 75 so they BLOCK on their own: a request
// that is only FLAGGED still runs, and a depth bomb must never run.
export function evaluate(analysis, extraFindings = []) {
  const findings = [...extraFindings];
  const add = (type, points, detail) => findings.push({ type, points, detail });

  if (analysis?.malformed) {
    add('malformed_query', 10, 'query could not be parsed');
  } else if (analysis?.introspection && !isProd) {
    // Development: Apollo Sandbox must be able to read the schema, so the normal
    // limits are skipped for pure introspection queries (still capped).
    if (analysis.depth > MAX_INTROSPECTION_DEPTH) {
      add('depth_limit', 75, `introspection depth ${analysis.depth} > ${MAX_INTROSPECTION_DEPTH}`);
    }
  } else if (analysis) {
    // Production: introspection is switched off in Apollo, so asking for the schema
    // is reconnaissance. It is flagged and the normal limits still apply.
    if (analysis.introspection) add('introspection_attempt', 40, 'schema introspection in production');
    if (analysis.depth > config.maxDepth) add('depth_limit', 75, `depth ${analysis.depth} > ${config.maxDepth}`);
    if (analysis.cost > config.maxCost) add('complexity_limit', 75, `cost ${analysis.cost} > ${config.maxCost}`);
    if (analysis.budgetExceeded) add('query_bomb', 75, 'query expands into too many fields');
    if (analysis.fields > config.maxFields) add('field_count', 30, `${analysis.fields} fields > ${config.maxFields}`);
    if (analysis.aliases > config.maxAliases) add('alias_abuse', 40, `${analysis.aliases} aliases > ${config.maxAliases}`);
  }

  const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
  const decision = score >= config.thresholds.block ? 'BLOCK' : score >= config.thresholds.flag ? 'FLAG' : 'ALLOW';
  const top = [...findings].sort((a, b) => b.points - a.points)[0];

  return { score, decision, attackType: top ? top.type : 'none', findings };
}
