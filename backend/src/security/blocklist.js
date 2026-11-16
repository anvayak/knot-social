import BlockedIp from '../models/BlockedIp.js';
import { config } from './config.js';

const blocks = new Map();  // ip -> { until (ms), reason }
const strikes = new Map(); // ip -> [timestamps]

export const normalizeIp = (ip = '') => ip.replace(/^::ffff:/, '');

// Re-load unexpired blocks after a server restart
export async function loadBlocks() {
  const rows = await BlockedIp.find({ blockedUntil: { $gt: new Date() } });
  rows.forEach((r) => blocks.set(r.ip, { until: r.blockedUntil.getTime(), reason: r.reason }));
  console.log(`Security: ${rows.length} active IP block(s) loaded`);
}

export function isBlocked(ip) {
  const b = blocks.get(ip);
  if (!b) return null;
  if (b.until <= Date.now()) {
    blocks.delete(ip);
    return null;
  }
  return b;
}

export function blockIp(ip, reason, minutes = config.blockMinutes) {
  const until = Date.now() + minutes * 60_000;
  blocks.set(ip, { until, reason });
  strikes.delete(ip);
  BlockedIp.findOneAndUpdate(
    { ip },
    { ip, reason, blockedUntil: new Date(until) },
    { upsert: true }
  ).catch((e) => console.error('blocklist save failed:', e.message));
  console.log(`Security: BLOCKED ${ip} for ${minutes} min (${reason})`);
}

// Returns true if this strike caused the IP to be blocked
export function addStrike(ip, reason) {
  const now = Date.now();
  const list = (strikes.get(ip) || []).filter((t) => now - t < config.strikes.windowMs);
  list.push(now);
  strikes.set(ip, list);
  if (list.length >= config.strikes.limit) {
    blockIp(ip, `${list.length} violations, last: ${reason}`);
    return true;
  }
  return false;
}

export async function unblockIp(ip) {
  blocks.delete(ip);
  strikes.delete(ip);
  await BlockedIp.deleteOne({ ip });
}

export function resetBlocks() {
  blocks.clear();
  strikes.clear();
  BlockedIp.deleteMany({}).catch(() => {});
}
