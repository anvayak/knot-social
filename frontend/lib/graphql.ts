'use client'
import { mockBlockedIps, mockEvents, mockPosts, mockStats, mockUser } from './mock'
export class GatewayError extends Error { code:string; status:number; riskScore?:number; reasons:string[]; ipBlocked:boolean; retryAfterSeconds?:number; constructor(message:string,code:string,status:number,extra:Partial<GatewayError>={}){super(message);this.name='GatewayError';this.code=code;this.status=status;this.riskScore=extra.riskScore;this.reasons=extra.reasons||[];this.ipBlocked=extra.ipBlocked||false;this.retryAfterSeconds=extra.retryAfterSeconds} }
export async function gql<T>(query:string,variables?:Record<string,unknown>):Promise<T>{
 if(process.env.NEXT_PUBLIC_USE_MOCK!=='false'){
  const token=typeof window!=='undefined'?localStorage.getItem('knot_token'):null
  const mockRole=token==='mock-user-token'?'user':token==='mock-admin-token'?'admin':undefined
  return mockResolver<T>(query,{...variables,__mockRole:mockRole})
 }
 const token=typeof window!=='undefined'?localStorage.getItem('knot_token'):null
 const response=await fetch(process.env.NEXT_PUBLIC_GRAPHQL_URL||'http://localhost:4000/graphql',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify({query,variables})})
 const body=await response.json()
 if(body.errors?.[0]){const e=body.errors[0];throw new GatewayError(e.message,e.extensions?.code||'UNKNOWN',response.status,{riskScore:e.extensions?.riskScore,reasons:e.extensions?.reasons||[],ipBlocked:e.extensions?.ipBlocked,retryAfterSeconds:e.extensions?.retryAfterSeconds})}
 return body.data as T
}
async function mockResolver<T>(query:string,v?:Record<string,unknown>):Promise<T>{await new Promise(r=>setTimeout(r,180));const s=query.replace(/\s+/g,' ').toLowerCase();let result:any={}
 if(s.includes('securitystats'))result={securityStats:mockStats}
 else if(s.includes('securityevents'))result={securityEvents:mockEvents.filter(e=>!v?.decision||e.decision===v.decision).slice(0,Number(v?.limit||50))}
 else if(s.includes('blockedips'))result={blockedIps:mockBlockedIps}
 else if(s.includes('unblockip')){const idx=mockBlockedIps.findIndex(x=>x.ip===v?.ip);if(idx>=0)mockBlockedIps.splice(idx,1);mockStats.activeBlockedIps=mockBlockedIps.length;result={unblockIp:true}}
 else if(s.includes('signup')||s.includes('login')){if(v?.email==='blocked@example.com')throw new GatewayError('Request blocked by Aegis AI','SECURITY_BLOCKED',403,{riskScore:94,reasons:['Repeated authentication attempts'],retryAfterSeconds:300});result={...(s.includes('signup')?{signup:{token:'mock-user-token',user:{...mockUser,username:v?.username||'newuser',email:v?.email||'user@example.com',role:'user'}}}:{login:{token:'mock-admin-token',user:mockUser}})}}
 else if(s.includes('query me'))result={me:v?.__mockRole==='user'?{...mockUser,role:'user'}:mockUser}
 else if(s.includes('feed'))result={feed:mockPosts}
 else if(s.includes('createpost')){const post={id:`p-${Date.now()}`,content:String(v?.content||''),author:mockUser,likesCount:0,likedByMe:false,replies:[],createdAt:new Date().toISOString()};mockPosts.unshift(post);result={createPost:post}}
 else if(s.includes('togglelike')){const p=mockPosts.find(x=>x.id===v?.postId)||mockPosts[0];p.likedByMe=!p.likedByMe;p.likesCount+=p.likedByMe?1:-1;result={toggleLike:p}}
 else if(s.includes('addreply')){const p=mockPosts.find(x=>x.id===v?.postId)||mockPosts[0];const reply={id:`r-${Date.now()}`,content:String(v?.content||''),author:mockUser,createdAt:new Date().toISOString()};p.replies.push(reply);result={addReply:reply}}
 else if(s.includes('deletepost')){const i=mockPosts.findIndex(x=>x.id===v?.id);if(i>=0)mockPosts.splice(i,1);result={deletePost:true}}
 else result={}
 return result as T
}
