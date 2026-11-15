// Express middleware that runs BEFORE Apollo on /graphql.
// Day 1: pass-through. Day 2/3 we add, in this order:
//   1. IP block-list check
//   2. Rate limiter
//   3. GraphQL AST analyzer (depth, complexity, field count, aliases)
//   4. Payload scanner (SQLi, NoSQLi, XSS, SSRF, command injection)
//   5. Risk score -> ALLOW / FLAG / BLOCK, then log a SecurityEvent
export function securityPipeline(req, res, next) {
  next();
}
