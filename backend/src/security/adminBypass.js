import jwt from 'jsonwebtoken';
import { parse, Kind } from 'graphql';

// The admin console must keep working while an attacker's IP is blocked or rate
// limited (in a demo, attacker and admin share one machine). So a request carrying
// a valid ADMIN token whose top-level fields are ONLY admin-console operations skips
// the IP block and rate limit. The resolvers still re-check the admin role in the
// database, so a stale or forged claim gains nothing.
const ADMIN_CONSOLE_FIELDS = new Set(['securityStats', 'securityEvents', 'blockedIps', 'unblockIp']);

export function isAdminConsoleRequest(req, query) {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ') || !query || query.length > 3000) return false;

    const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    if (payload.role !== 'admin') return false;

    const doc = parse(query);
    const ops = doc.definitions.filter((d) => d.kind === Kind.OPERATION_DEFINITION);
    if (!ops.length) return false;
    return ops.every((op) =>
      op.selectionSet.selections.every(
        (sel) => sel.kind === Kind.FIELD && ADMIN_CONSOLE_FIELDS.has(sel.name.value)
      )
    );
  } catch {
    return false;
  }
}