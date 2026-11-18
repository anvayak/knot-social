import SecurityEvent from '../models/SecurityEvent.js';
import BlockedIp from '../models/BlockedIp.js';

const DECISIONS = ['ALLOW', 'FLAG', 'BLOCK'];

export async function getStats(hours = 24) {
  const since = new Date(Date.now() - hours * 3600_000);
  const match = { createdAt: { $gte: since } };

  const [byDecision, byType, byHour, activeBlockedIps] = await Promise.all([
    SecurityEvent.aggregate([{ $match: match }, { $group: { _id: '$decision', n: { $sum: 1 } } }]),
    SecurityEvent.aggregate([
      { $match: { ...match, attackType: { $ne: 'none' } } },
      { $group: { _id: '$attackType', n: { $sum: 1 } } },
      { $sort: { n: -1 } },
    ]),
    SecurityEvent.aggregate([
      { $match: match },
      {
        $group: {
          _id: { hour: { $dateToString: { format: '%Y-%m-%dT%H:00', date: '$createdAt' } }, decision: '$decision' },
          n: { $sum: 1 },
        },
      },
    ]),
    BlockedIp.countDocuments({ blockedUntil: { $gt: new Date() } }),
  ]);

  const count = (d) => byDecision.find((x) => x._id === d)?.n || 0;
  const allowed = count('ALLOW');
  const flagged = count('FLAG');
  const blocked = count('BLOCK');

  const hours_ = new Map();
  for (const row of byHour) {
    const point = hours_.get(row._id.hour) || { hour: row._id.hour, allowed: 0, flagged: 0, blocked: 0 };
    if (row._id.decision === 'ALLOW') point.allowed = row.n;
    if (row._id.decision === 'FLAG') point.flagged = row.n;
    if (row._id.decision === 'BLOCK') point.blocked = row.n;
    hours_.set(row._id.hour, point);
  }

  return {
    total: allowed + flagged + blocked,
    allowed,
    flagged,
    blocked,
    activeBlockedIps,
    byAttackType: byType.map((t) => ({ attackType: t._id, count: t.n })),
    timeline: [...hours_.values()].sort((a, b) => a.hour.localeCompare(b.hour)),
  };
}

export function getEvents({ limit = 50, decision } = {}) {
  const filter = {};
  const d = decision ? String(decision).toUpperCase() : null;
  if (d && DECISIONS.includes(d)) filter.decision = d;
  return SecurityEvent.find(filter)
    .sort({ createdAt: -1 })
    .limit(Math.min(Math.max(limit, 1), 200));
}

export function getBlockedIps() {
  return BlockedIp.find({ blockedUntil: { $gt: new Date() } }).sort({ blockedUntil: -1 });
}