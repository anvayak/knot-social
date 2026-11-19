// Real attacks fired at the real API, so Aegis can be demonstrated end to end.
export const GRAPHQL_URL = process.env.NEXT_PUBLIC_GRAPHQL_URL || 'http://localhost:4000/graphql'
export const RESET_URL = GRAPHQL_URL.replace(/\/graphql\/?$/, '') + '/dev/security/reset'

export type Attack = {
  id: string
  category: string
  name: string
  description: string
  expected: 'ALLOW' | 'BLOCK'
  repeat?: number
  body?: unknown
  build?: () => unknown
}

const DEEP = '{ feed { author { posts { author { posts { author { posts { id } } } } } } } }'
const FRAGMENTS =
  'query { feed { ...A } } fragment A on Post { author { ...B } } fragment B on User { posts { ...C } } fragment C on Post { author { posts { author { posts { id } } } } }'

export const ATTACKS: Attack[] = [
  { id: 'normal', category: 'Control', name: 'Normal feed query', description: 'A legitimate request. It must be allowed.', expected: 'ALLOW', body: { query: '{ feed { id content author { username } } }' } },
  { id: 'deep', category: 'DoS', name: 'Deeply nested query', description: 'author > posts > author > posts ... exhausts the database.', expected: 'BLOCK', body: { query: DEEP } },
  { id: 'fragment', category: 'DoS', name: 'Depth hidden in fragments', description: 'The same nesting split across fragments to dodge a naive depth check.', expected: 'BLOCK', body: { query: FRAGMENTS } },
  {
    id: 'alias', category: 'Brute force', name: '30 aliased logins in one request', description: 'Many password guesses packed into a single HTTP request.', expected: 'BLOCK',
    build: () => ({ query: 'mutation { ' + Array.from({ length: 30 }, (_, i) => `a${i}: login(email:"victim@example.com", password:"guess${i}") { token }`).join(' ') + ' }' }),
  },
  { id: 'loginflood', category: 'Brute force', name: '15 rapid login attempts', description: 'Password guessing. Attempts beyond the limit are throttled.', expected: 'BLOCK', repeat: 15, body: { query: 'mutation { login(email:"victim@example.com", password:"wrong") { token } }' } },
  { id: 'flood', category: 'DoS', name: 'Request flood (130 requests)', description: 'A burst far above the per-IP rate limit.', expected: 'BLOCK', repeat: 130, body: { query: '{ me { id } }' } },
  { id: 'batch', category: 'DoS', name: 'Batched request array', description: 'An array of operations sent in one request.', expected: 'BLOCK', body: [{ query: '{ me { id } }' }, { query: '{ me { id } }' }] },
  { id: 'oversized', category: 'DoS', name: 'Oversized query (6000 chars)', description: 'A huge query meant to burn parsing time.', expected: 'BLOCK', build: () => ({ query: '{ me { id } }' + ' '.repeat(6000) }) },
  { id: 'sqli1', category: 'Injection', name: 'SQL injection in login', description: "Classic ' OR '1'='1' tautology in the email field.", expected: 'BLOCK', body: { query: `mutation { login(email: "admin' OR '1'='1' --", password: "x") { token } }` } },
  { id: 'sqli2', category: 'Injection', name: 'UNION-based SQL injection', description: 'Tries to read the users table through a post.', expected: 'BLOCK', body: { query: `mutation { createPost(content: "x' UNION SELECT username, password FROM users --") { id } }` } },
  { id: 'xss', category: 'Injection', name: 'Stored XSS payload', description: 'A script tag saved inside a post.', expected: 'BLOCK', body: { query: 'mutation { createPost(content: "<script>alert(document.cookie)</script>") { id } }' } },
  { id: 'ssrf', category: 'Injection', name: 'SSRF to cloud metadata', description: 'Points the server at the cloud metadata address.', expected: 'BLOCK', body: { query: 'mutation { createPost(content: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") { id } }' } },
  { id: 'cmdi', category: 'Injection', name: 'Command injection', description: 'Shell commands chained onto normal text.', expected: 'BLOCK', body: { query: 'mutation { createPost(content: "hello; cat /etc/passwd && rm -rf /") { id } }' } },
  { id: 'nosqli', category: 'Injection', name: 'NoSQL operator injection', description: 'A Mongo operator object sent through a variable.', expected: 'BLOCK', body: { query: 'mutation($e: String!) { login(email: $e, password: "x") { token } }', variables: { e: '{"$ne": null}' } } },
]

type Raw = { status: number; json: any; latencyMs: number }

export async function rawGraphql(body: unknown): Promise<Raw> {
  const started = performance.now()
  const token = typeof window !== 'undefined' ? localStorage.getItem('knot_token') : null
  try {
    const res = await fetch(GRAPHQL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    })
    let json: any = null
    try { json = await res.json() } catch { /* not JSON */ }
    return { status: res.status, json, latencyMs: Math.round(performance.now() - started) }
  } catch {
    return { status: 0, json: null, latencyMs: Math.round(performance.now() - started) }
  }
}

const isBlocked = (r: Raw) => {
  const code = r.json?.errors?.[0]?.extensions?.code
  return r.status === 403 || r.status === 429 || code === 'SECURITY_BLOCKED' || code === 'IP_BLOCKED'
}

export async function resetGateway(): Promise<boolean> {
  try { return (await fetch(RESET_URL, { method: 'POST' })).ok } catch { return false }
}

export type AttackResult = {
  status: number
  code?: string
  riskScore?: number
  reasons: string[]
  latencyMs: number
  blocked: boolean
  counts: Record<string, number>
  total: number
}

export async function runAttack(a: Attack, onProgress?: (done: number, total: number) => void): Promise<AttackResult> {
  const total = a.repeat ?? 1
  const counts: Record<string, number> = {}
  let first: Raw | null = null
  let last: Raw | null = null
  let blocked = false
  let latency = 0
  for (let i = 0; i < total; i++) {
    const r = await rawGraphql(a.build ? a.build() : a.body)
    counts[r.status] = (counts[r.status] || 0) + 1
    latency += r.latencyMs
    last = r
    if (isBlocked(r)) { blocked = true; if (!first) first = r }
    onProgress?.(i + 1, total)
  }
  const shown = first ?? last
  const ext = shown?.json?.errors?.[0]?.extensions ?? {}
  return { status: shown?.status ?? 0, code: ext.code, riskScore: ext.riskScore, reasons: ext.reasons ?? [], latencyMs: Math.round(latency / total), blocked, counts, total }
}

export const passed = (a: Attack, r: AttackResult) => (a.expected === 'BLOCK' ? r.blocked : !r.blocked)