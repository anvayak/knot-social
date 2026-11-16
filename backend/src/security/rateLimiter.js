// Sliding-window rate limiter, kept in memory (fine for a single-server project).
const windows = new Map(); // key -> [timestamps]

export function hit(key, { limit, windowMs }, weight = 1) {
  const now = Date.now();
  const arr = (windows.get(key) || []).filter((t) => now - t < windowMs);
  for (let i = 0; i < Math.min(weight, 100); i++) arr.push(now);
  if (arr.length > limit * 3) arr.splice(0, arr.length - limit * 3); // cap memory per key
  windows.set(key, arr);
  return { exceeded: arr.length > limit, count: arr.length, limit };
}

export function resetLimits() {
  windows.clear();
}

// Drop stale keys every 5 minutes so the Map can't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, arr] of windows) {
    if (!arr.length || now - arr[arr.length - 1] > 120_000) windows.delete(key);
  }
}, 300_000).unref();
