// All security limits live here so you can tune them (and explain them in the viva).
export const config = {
  maxQueryLength: 5000,   // characters
  maxDepth: 6,            // nesting levels
  maxCost: 2000,          // weighted cost (see queryAnalyzer.js)
  maxFields: 50,          // total fields in one request
  maxAliases: 5,          // aliases in one request

  // How many rows a list field is assumed to return (used for the cost estimate)
  listSize: { feed: 20, posts: 5, replies: 5 },
  maxPageSize: 50,

  rate: {
    global: { limit: 100, windowMs: 60_000 }, // requests per IP per minute
    auth: { limit: 10, windowMs: 60_000 },    // login/signup attempts per IP per minute
  },

  // 5 blocked requests within 10 minutes => the IP itself gets blocked
  strikes: { limit: 5, windowMs: 10 * 60_000 },
  blockMinutes: Number(process.env.BLOCK_MINUTES) || 5,

  // risk score -> decision
  thresholds: { flag: 31, block: 71 },
};
