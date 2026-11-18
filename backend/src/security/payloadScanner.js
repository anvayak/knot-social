// Looks for attack patterns inside the VALUES a client sends (string arguments and
// variables). Each rule: [attack type, risk points, name, pattern].
// 75 points = confident attack (blocks on its own), 40 = suspicious (flag only).
const RULES = [
  // SQL injection
  ['sqli', 75, 'tautology (OR 1=1)', /['"]\s*(?:or|and)\s+['"\w]+\s*=\s*['"\w]+/i],
  ['sqli', 75, 'numeric tautology', /\b(?:or|and)\s+\d+\s*=\s*\d+/i],
  ['sqli', 75, 'UNION SELECT', /\bunion(?:\s|\/\*[\s\S]*?\*\/)+(?:all(?:\s|\/\*[\s\S]*?\*\/)+)?select\b/i],
  ['sqli', 75, 'stacked query', /;\s*(?:drop|delete|insert|update|alter|truncate|create)\s+(?:table|from|into|database)\b/i],
  ['sqli', 75, 'time-based probe', /\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay/i],
  ['sqli', 75, 'schema probing', /\binformation_schema\b|\bxp_cmdshell\b|\bsqlite_master\b/i],
  ['sqli', 40, 'quote + SQL comment at end', /'\s*\)?\s*(?:--|#|\/\*)\s*$/],

  // NoSQL injection
  ['nosqli', 75, 'Mongo operator object', /\{\s*["']?\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|or|and|not|expr)["']?\s*:/i],
  ['nosqli', 75, '$where JavaScript', /\$where\b/i],

  // Cross-site scripting
  ['xss', 75, '<script> tag', /<\s*\/?\s*script\b/i],
  ['xss', 75, 'inline event handler', /<[^>]*\bon[a-z]+\s*=/i],
  ['xss', 75, 'javascript: URL', /\bjavascript:\S/i],
  ['xss', 40, 'risky HTML tag', /<\s*(?:iframe|object|embed|svg|img|body|link|meta|style)\b/i],

  // Server-side request forgery
  ['ssrf', 75, 'cloud metadata address', /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i],
  ['ssrf', 75, 'internal address', /\bhttps?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/i],
  ['ssrf', 75, 'non-HTTP scheme', /\b(?:file|gopher|dict|ftp|ldap):\/\//i],

  // Command injection
  ['command_injection', 75, 'shell chaining', /[;&|`]\s*(?:cat|ls|rm|wget|curl|nc|ncat|bash|sh|zsh|powershell|cmd|chmod|chown|python3?|perl|nslookup)\s+(?:-\w+|\/|~|\.\/|https?:)/i],
  ['command_injection', 75, 'recon command', /[;&|`]\s*(?:whoami|uname|ifconfig|ipconfig)\b/i],
  ['command_injection', 75, 'sensitive system file', /\/etc\/(?:passwd|shadow|hosts)\b|\bc:\\windows\\system32/i],
  ['command_injection', 75, 'dangerous command', /\brm\s+-rf?\b|\bchmod\s+[0-7]{3,4}\b|\bnc\s+-e\b|\/bin\/(?:ba)?sh\b|\bcmd\.exe\b|\bpowershell\.exe\b/i],
  ['command_injection', 40, 'command substitution', /\$\(\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh|rm|uname|echo)\b/i],
];

const MAX_STRINGS = 200;
const MAX_LEN = 5000;

const safeDecode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

// Pull every string out of the variables object (skipping passwords)
function collectVariables(value, out, state, depth = 0) {
  if (depth > 6 || out.length >= MAX_STRINGS) return;
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectVariables(v, out, state, depth + 1));
  else if (value && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) {
      if (key.toLowerCase() === 'password') continue;
      if (key.startsWith('$')) state.operatorKey = true; // {"$ne": ...} as an object
      collectVariables(v, out, state, depth + 1);
    }
  }
}

export function scanPayload(strings = [], variables) {
  const inputs = [...strings];
  const state = { operatorKey: false };

  let vars = variables;
  if (typeof vars === 'string') {
    try {
      vars = JSON.parse(vars);
    } catch {
      // not JSON: scan it as plain text
    }
  }
  collectVariables(vars, inputs, state);

  const best = new Map(); // attack type -> { points, names }
  const record = (type, points, name) => {
    const cur = best.get(type) || { points: 0, names: [] };
    cur.points = Math.max(cur.points, points);
    if (!cur.names.includes(name)) cur.names.push(name);
    best.set(type, cur);
  };

  if (state.operatorKey) record('nosqli', 75, 'Mongo operator key in variables');

  for (const raw of inputs.slice(0, MAX_STRINGS)) {
    const text = String(raw).slice(0, MAX_LEN);
    // also test the URL-decoded form, so %3Cscript%3E cannot sneak past
    const forms = [text, safeDecode(text)];
    for (const [type, points, name, pattern] of RULES) {
      if (forms.some((f) => pattern.test(f))) record(type, points, name);
    }
  }

  return [...best].map(([type, { points, names }]) => ({ type, points, detail: names.join(', ') }));
}