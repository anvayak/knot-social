export type User = { id: string; username: string; email: string; role: string; createdAt: string; posts: Post[] }
export type Reply = { id: string; content: string; author: User; createdAt: string }
export type Post = { id: string; content: string; author: User; likesCount: number; likedByMe: boolean; replies: Reply[]; createdAt: string }
export type SecurityEvent = { id: string; ip: string; attackType: string; riskScore: number; decision: string; snippet: string; createdAt: string }
export type BlockedIp = { ip: string; reason: string; blockedUntil: string }
export const attackTypes = ['depth_limit','complexity_limit','rate_limit','auth_rate_limit','batching','oversized_query','alias_abuse','sqli','xss','ssrf','command_injection','introspection_attempt','none']
const decisions = ['ALLOW','ALLOW','ALLOW','FLAG','BLOCK']
const snippets = ['query Feed { feed(limit: 20) { id content } }','mutation CreatePost { createPost(content: "Hello, Knot!") { id } }','query Account { me { id username } }','query Search { feed { author { username } } }','mutation Login { login(email: "•••", password: "•••") { token } }']
export const mockUser: User = { id:'u-admin', username:'alex', email:'alex@knot.social', role:'admin', createdAt:new Date().toISOString(), posts:[] }
export const mockEvents: SecurityEvent[] = Array.from({length:60},(_,i)=>{
 const attackType=attackTypes[(i*7+3)%attackTypes.length], decision=decisions[(i*3+2)%decisions.length]
 return { id:`evt-${i+1}`, ip:`${[34,45,103,172,198][i%5]}.${(i*31+24)%255}.${(i*13+77)%255}.${(i*17+8)%255}`, attackType, riskScore:decision==='BLOCK'?78+(i%22):decision==='FLAG'?48+(i%30):4+(i%35), decision, snippet:snippets[i%snippets.length], createdAt:new Date(Date.now()-i*97000).toISOString() }
})
export const mockBlockedIps: BlockedIp[] = [
 {ip:'198.51.100.24',reason:'Repeated rate limit violations',blockedUntil:new Date(Date.now()+19*60000).toISOString()},
 {ip:'203.0.113.87',reason:'High-risk injection attempts',blockedUntil:new Date(Date.now()+42*60000).toISOString()},
 {ip:'192.0.2.156',reason:'Authentication abuse detected',blockedUntil:new Date(Date.now()+8*60000).toISOString()},
]
export const mockStats = { total:12842, allowed:11903, flagged:611, blocked:328, activeBlockedIps:mockBlockedIps.length, byAttackType:attackTypes.map((attackType,i)=>({attackType,count:[220,164,198,88,61,39,34,17,13,9,8,7,11991][i]})), timeline:Array.from({length:12},(_,i)=>({hour:`${String((new Date().getHours()-11+i+24)%24).padStart(2,'0')}:00`,allowed:340+(i*37)%170,flagged:10+(i*7)%24,blocked:3+(i*5)%19})) }
export const mockPosts: Post[] = [
 {id:'p1',content:'We just shipped a quieter, faster feed. Every request still gets the same careful inspection from Aegis AI.',author:mockUser,likesCount:24,likedByMe:false,replies:[{id:'r1',content:'The little details make a difference.',author:{...mockUser,id:'u2',username:'jules',role:'user'},createdAt:new Date(Date.now()-3600000).toISOString()}],createdAt:new Date(Date.now()-7200000).toISOString()},
 {id:'p2',content:'Security should feel invisible when everything is working — and clear when it matters.',author:{...mockUser,id:'u2',username:'jules',role:'user'},likesCount:18,likedByMe:true,replies:[],createdAt:new Date(Date.now()-86400000).toISOString()},
 {id:'p3',content:'A small reminder: thoughtful rate limits protect the good conversations too.',author:{...mockUser,id:'u3',username:'samira',role:'user'},likesCount:9,likedByMe:false,replies:[],createdAt:new Date(Date.now()-172800000).toISOString()},
]
