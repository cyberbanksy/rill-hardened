import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {D1} from './d1.mjs';
import worker from '../src/index.ts';
import {readOwner} from '../src/security/auth.ts';
import {encodeGuid} from '../src/jellyfin/ids.ts';
const origin='https://rill.example';
function env(){return {DB:new D1(),RILL_DATA_KEY:Buffer.alloc(32,9).toString('base64'),RILL_SETUP_TOKEN:'test-provision',RILL_SECRET:'test-signing-key'};}
function req(path,body={},cookie='',extra={}) {return new Request(origin+path,{method:'POST',headers:{origin,'content-type':'application/json','cf-connecting-ip':'203.0.113.50',...(cookie?{cookie}:{}),...extra},body:JSON.stringify(body)});}
const cookies=res=>res.headers.getSetCookie().map(c=>c.split(';')[0]);
async function setup(e,config={}){const res=await worker.fetch(req('/api/account/save',{setupToken:e.RILL_SETUP_TOKEN,config:{...config,jellyfin:{username:'owner',password:'correct-password'}}}),e);assert.equal(res.status,200);return {res,cookie:cookies(res).find(c=>c.startsWith('__Host-rill_owner=')),data:await res.json()};}
async function mockFetch(handler,work){const original=globalThis.fetch,calls=[];globalThis.fetch=async(url,init)=>{calls.push(String(url));if(String(url).startsWith('https://cloudflare-dns.com/'))return new Response(JSON.stringify({Status:0,Answer:[{type:1,data:'8.8.8.8'}]}));return handler(String(url),init);};try{return await work(calls);}finally{globalThis.fetch=original;}}

test('owner cookies use __Host- names; setup also issues a device cookie',async()=>{
 const e=env();const {res}=await setup(e);const set=res.headers.getSetCookie();
 assert.ok(set.some(c=>c.startsWith('__Host-rill_owner=')&&/; Path=\/;/.test(c)&&/; Secure/.test(c)&&!/Domain=/i.test(c)));
 assert.ok(set.some(c=>c.startsWith('__Host-rill_device=')&&/HttpOnly/.test(c)&&/; Secure/.test(c)));
 e.DB.close();
});
test('username and password changes require the current password and a 12 character minimum',async()=>{
 const e=env();const {cookie,data}=await setup(e);const generation=(await readOwner(e)).auth_generation;
 const change=(extra,jellyfin)=>worker.fetch(req('/api/account/save',{...extra,config:{...data.config,jellyfin:{...data.config.jellyfin,...jellyfin}}},cookie),e);
 assert.equal((await change({},{password:'another-password'})).status,403);
 assert.equal((await change({currentPassword:'wrong-password'},{password:'another-password'})).status,403);
 assert.equal((await change({},{username:'renamed'})).status,403);
 assert.equal((await change({currentPassword:'correct-password'},{password:'short-pass'})).status,400);
 assert.equal((await readOwner(e)).username,'owner');assert.equal((await readOwner(e)).auth_generation,generation);
 // Ordinary settings saves still work without re-entering the password.
 assert.equal((await worker.fetch(req('/api/account/save',{config:{...data.config,name:'Renamed server'}},cookie),e)).status,200);
 assert.equal((await change({currentPassword:'correct-password'},{username:'renamed'})).status,200);assert.equal((await readOwner(e)).username,'renamed');
 e.DB.close();
});
test('wrong current passwords are throttled like logins',async()=>{
 const e=env();const {cookie,data}=await setup(e);
 const statuses=[];for(let i=0;i<7;i++)statuses.push((await worker.fetch(req('/api/account/save',{currentPassword:'wrong-password',config:{...data.config,jellyfin:{...data.config.jellyfin,password:'another-password'}}},cookie),e)).status);
 assert.ok(statuses.includes(429),String(statuses));e.DB.close();
});
test('a signed-in browser keeps its own login bucket while strangers trip the account lockout',async()=>{
 const e=env();await setup(e);
 const login=await worker.fetch(req('/api/account/login',{username:'owner',password:'correct-password'}),e);assert.equal(login.status,200);
 const device=cookies(login).find(c=>c.startsWith('__Host-rill_device='));assert.ok(device);
 for(let i=0;i<8;i++)await worker.fetch(req('/api/account/login',{username:'owner',password:'wrong'},'',{'cf-connecting-ip':`198.51.100.${i+1}`}),e);
 assert.equal((await worker.fetch(req('/api/account/login',{username:'owner',password:'correct-password'},'',{'cf-connecting-ip':'198.51.100.99'}),e)).status,429);
 assert.equal((await worker.fetch(req('/api/account/login',{username:'owner',password:'correct-password'},device,{'cf-connecting-ip':'198.51.100.99'}),e)).status,200);
 // A forged or tampered device cookie falls back to the shared account bucket.
 assert.equal((await worker.fetch(req('/api/account/login',{username:'owner',password:'correct-password'},device.replace(/.$/,c=>c==='0'?'1':'0'),{'cf-connecting-ip':'198.51.100.99'}),e)).status,429);
 e.DB.close();
});
test('anonymous image requests cannot resolve forged item IDs through add-ons; user list is hidden',async()=>{
 const e=env();await setup(e,{providers:{movie:'cinemeta',series:'cinemeta',anime:'off'},addons:{meta:['https://addon.example/private-key/manifest.json']}});const id=encodeGuid({kind:'movie',source:'imdb',num:133093,anime:false});
 await mockFetch(()=>new Response('{}'),async calls=>{
  const res=await worker.fetch(new Request(`${origin}/Items/${id}/Images/Primary`),e);assert.equal(res.status,404);
  assert.deepEqual(calls,[]);
 });
 const users=await worker.fetch(new Request(`${origin}/Users/Public`),e);assert.equal(users.status,200);assert.deepEqual(await users.json(),[]);
 e.DB.close();
});
test('settings page sends a hash-pinned CSP that matches its inline script and forbids framing',async()=>{
 const e=env();const res=await worker.fetch(new Request(origin+'/'),e);const csp=res.headers.get('content-security-policy');
 assert.match(csp,/frame-ancestors 'none'/);assert.match(csp,/default-src 'none'/);assert.equal(res.headers.get('x-frame-options'),'DENY');
 const html=await res.text();const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);assert.equal(scripts.length,1);
 assert.ok(csp.includes(`'sha256-${createHash('sha256').update(scripts[0]).digest('base64')}'`));
 assert.equal(/\son[a-z]+=/i.test(html.replace(/<script>[\s\S]*?<\/script>/,'')),false);
 e.DB.close();
});
test('provider verification links must be https',async()=>{
 const e=env();const {cookie}=await setup(e);
 await mockFetch(()=>new Response(JSON.stringify({device_code:'d',user_code:'u',verification_url:'javascript:alert(1)',expires_in:600,interval:5})),async()=>{
  const res=await worker.fetch(req('/api/oauth/trakt/device',{clientId:'id'},cookie),e);assert.equal(res.status,200);assert.equal((await res.json()).verificationUrl,'https://trakt.tv/activate');
 });
 e.DB.close();
});
