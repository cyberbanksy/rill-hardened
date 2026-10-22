import {test} from 'node:test';
import assert from 'node:assert/strict';
import {D1} from './d1.mjs';
import worker from '../src/index.ts';
import {ensureSchema} from '../src/storage/migrate.ts';
import {normalizeConfig} from '../src/config/schema.ts';
import {encodeConfig} from '../src/config/codec.ts';
import {loadConfig,migrateSecrets,publicConfig,mergePrivate} from '../src/security/secrets.ts';
import {claimOwner,helperQuota,loginThrottle,readOwner} from '../src/security/auth.ts';
import {sha256} from '../src/util/bytes.ts';
import {mintToken,verifyToken,startQuickConnect,approveQuickConnect,claimQuickConnect} from '../src/jellyfin/auth.ts';
import {renderPage} from '../src/ui/page.ts';
import {Script} from 'node:vm';
const origin='https://rill.example';
function env(){return {DB:new D1(),RILL_DATA_KEY:Buffer.alloc(32,9).toString('base64'),RILL_SETUP_TOKEN:'test-provision',RILL_SECRET:'test-signing-key'};}
function req(path,body={},cookie='',extra={}) {return new Request(origin+path,{method:'POST',headers:{origin,'content-type':'application/json','cf-connecting-ip':'203.0.113.50',...(cookie?{cookie}:{}),...extra},body:JSON.stringify(body)});}
async function setup(e){const res=await worker.fetch(req('/api/account/save',{setupToken:e.RILL_SETUP_TOKEN,config:{jellyfin:{username:'owner',password:'correct-password'},addons:{stream:['https://addon.example/private-provider-key/manifest.json']},keys:{tmdb:'private-tmdb-key'},trackers:{trakt:{clientId:'id',accessToken:'private-tracker-token'}}}}),e);assert.equal(res.status,200);return {cookie:res.headers.get('set-cookie').split(';')[0],data:await res.json()};}

test('helper authentication and exact-origin guard precede work',async()=>{
 const e=env();
 for(const path of ['/api/recommendations/generate','/api/probe','/api/collections/import','/api/catalogs','/api/movielens/sync','/api/oauth/trakt/device'])assert.equal((await worker.fetch(req(path),e)).status,401,path);
 assert.equal((await worker.fetch(req('/api/account/status',{},'',{origin:'https://evil.rill.example'}),e)).status,403);
 assert.equal((await worker.fetch(req('/api/account/status',{},'',{origin:'null'}),e)).status,403);
 assert.equal((await worker.fetch(req('/api/account/status',{},'',{'content-type':'text/plain'}),e)).status,415);
 assert.equal((await e.DB.prepare('SELECT count(*) AS n FROM accounts').first()).n,0);
 const res=await worker.fetch(new Request(origin+'/System/Info/Public',{headers:{origin:'https://client.example'}}),e);
 assert.equal(res.headers.get('access-control-allow-origin'),'*');assert.equal(res.headers.has('access-control-allow-credentials'),false);
 e.DB.close();
});
test('claim is atomic and rejects all later unauthenticated saves',async()=>{
 const e=env();await ensureSchema(e.DB);
 const wins=await Promise.all([claimOwner(e,'a'.repeat(48),'one','password-1'),claimOwner(e,'b'.repeat(48),'two','password-2')]);assert.equal(wins.filter(Boolean).length,1);
 const winner=await readOwner(e);assert.equal(winner.username,wins[0]?'one':'two');
 assert.equal((await worker.fetch(req('/api/account/save',{config:{jellyfin:{username:'attacker',password:'attacker-password'}}}),e)).status,401);
 assert.equal((await readOwner(e)).username,winner.username);e.DB.close();
});
test('first setup requires provisioning token; client config is masked and storage encrypted',async()=>{
 const e=env();assert.equal((await worker.fetch(req('/api/account/save',{config:{jellyfin:{username:'owner',password:'correct-password'}}}),e)).status,403);
 const {cookie,data}=await setup(e);const text=JSON.stringify(data);
 for(const secret of ['correct-password','private-provider-key','private-tmdb-key','private-tracker-token'])assert.equal(text.includes(secret),false);
 assert.match(data.token,/^r1\./);
 const row=await e.DB.prepare('SELECT scope,config FROM accounts').first();assert.match(row.config,/^e1\./);const cfg=await loadConfig(row.config,e,row.scope);
 assert.equal(cfg.jellyfin.password,'');assert.equal(cfg.keys.tmdb,'private-tmdb-key');assert.equal(cfg.trackers.trakt.accessToken,'private-tracker-token');
 assert.match((await e.DB.prepare('SELECT value FROM credentials').first()).value,/^e1\./);
 const saved=await worker.fetch(req('/api/account/save',{config:{...data.config,installationKey:'f'.repeat(48),name:'Edited'}},cookie),e);assert.equal(saved.status,200);
 const after=await e.DB.prepare('SELECT scope,config FROM accounts').first();assert.equal(after.scope,row.scope);const active=await loadConfig(after.config,e,after.scope);assert.equal(active.keys.tmdb,'private-tmdb-key');assert.equal(active.addons.stream[0],cfg.addons.stream[0]);assert.equal(active.name,'Edited');
 const legacy=await encodeConfig(cfg);assert.equal((await worker.fetch(new Request(`${origin}/${legacy}/manifest.json`),e)).status,400);
 const manifest=await worker.fetch(new Request(`${origin}/${data.token}/manifest.json`),e);assert.equal(manifest.status,200);
 e.DB.close();
});
test('owner and Jellyfin sessions revoke on password change and logout-all; normal logout revokes cookie',async()=>{
 const e=env();const {cookie,data}=await setup(e);
 const login=await worker.fetch(req('/Users/AuthenticateByName',{Username:'owner',Pw:'correct-password'}),e);assert.equal(login.status,200);const bearer=(await login.json()).AccessToken;
 const owner=await readOwner(e),scope=(await sha256(owner.installation_key)).slice(0,32),row=await e.DB.prepare('SELECT config FROM accounts').first();const cfg=await loadConfig(row.config,e,scope);
 const ctx={cfg,env:e,scope,cfgToken:'',origin,lang:'en',tmdbKey:cfg.keys.tmdb};assert.ok(await verifyToken(ctx,bearer));
 const qc=await startQuickConnect(ctx,{client:'test',device:'test',deviceId:'test',version:'1'});assert.ok(await approveQuickConnect(ctx,qc.code));
 const rotated=await worker.fetch(req('/api/account/save',{currentPassword:'correct-password',config:{...data.config,jellyfin:{...data.config.jellyfin,password:'new-password'}}},cookie),e);assert.equal(rotated.status,200);const newCookie=rotated.headers.get('set-cookie').split(';')[0];
 assert.equal(await verifyToken(ctx,bearer),null);assert.equal(await claimQuickConnect(ctx,qc.secret),null);
 assert.equal((await worker.fetch(req('/api/account/load',{},cookie),e)).status,401);
 assert.equal((await worker.fetch(req('/Users/AuthenticateByName',{Username:'owner',Pw:'correct-password'}),e)).status,401);
 assert.equal((await worker.fetch(req('/Users/AuthenticateByName',{Username:'owner',Pw:'new-password'}),e)).status,200);
 assert.equal((await worker.fetch(req('/api/account/logout',{},newCookie),e)).status,200);
 assert.equal((await worker.fetch(req('/api/account/load',{},newCookie),e)).status,401);
 const relog=await worker.fetch(req('/api/account/login',{username:'owner',password:'new-password'}),e);assert.equal(relog.status,200);const relogCookie=relog.headers.get('set-cookie').split(';')[0];const fresh=await mintToken(ctx,'user','device');
 assert.equal((await worker.fetch(req('/api/account/logout-all',{},relogCookie),e)).status,403);assert.ok(await verifyToken(ctx,fresh));
 assert.equal((await worker.fetch(req('/api/account/logout-all',{currentPassword:'new-password'},relogCookie),e)).status,200);assert.equal(await verifyToken(ctx,fresh),null);
 assert.equal((await worker.fetch(new Request(`${origin}/${data.token}/manifest.json`),e)).status,400);
 e.DB.close();
});
test('D1 progressive throttles share owner account across both login paths and IPs; quotas atomic',async()=>{
 const e=env();await setup(e);
 for(let i=0;i<5;i++)assert.equal((await worker.fetch(req('/api/account/login',{username:'owner',password:'wrong'}),e)).status,401);
 const blocked=await worker.fetch(req('/Users/AuthenticateByName',{Username:'owner',Pw:'wrong'},'',{'cf-connecting-ip':'203.0.113.51'}),e);assert.equal(blocked.status,429);assert.ok(Number(blocked.headers.get('retry-after'))>=1);
 const successes=await Promise.all(Array.from({length:8},()=>helperQuota(e,'owner','work',2,3600000)));assert.equal(successes.filter(Boolean).length,2);
 e.DB.close();
});
test('existing owner migration retains login and scope, encrypts every config copy and refresh row',async()=>{
 const e=env();await ensureSchema(e.DB);const installation='a'.repeat(48);await claimOwner(e,installation,'existing','old-password');const scope=(await sha256(installation)).slice(0,32);
 const cfg=normalizeConfig({installationKey:installation,jellyfin:{username:'existing',password:'old-password'},addons:{stream:['https://addon.example/private-key/manifest.json']}});
 // Use an actual legacy representation retaining a password, unlike the hardened encoder.
 const legacy=Buffer.from(JSON.stringify(cfg)).toString('base64url');
 await e.DB.prepare('INSERT INTO accounts(scope,config,origin) VALUES(?,?,?)').bind(scope,legacy,origin).run();
 await e.DB.prepare('INSERT INTO recommendation_jobs(id,scope,config,origin,created,updated) VALUES(?,?,?,?,?,?)').bind('old-job',scope,legacy,origin,0,0).run();
 await e.DB.prepare('INSERT INTO credentials(scope,service,value) VALUES(?,?,?)').bind(scope,'trakt',JSON.stringify({accessToken:'private-token'})).run();
 await migrateSecrets(e);await migrateSecrets(e);
 for(const table of ['accounts','recommendation_jobs']){const row=await e.DB.prepare(`SELECT config FROM ${table}`).first();assert.match(row.config,/^e1\./);assert.equal((await loadConfig(row.config,e,scope)).jellyfin.password,'');}
 assert.match((await e.DB.prepare('SELECT value FROM credentials').first()).value,/^e1\./);
 const login=await worker.fetch(req('/api/account/login',{username:'existing',password:'old-password'}),e);assert.equal(login.status,200);assert.equal((await readOwner(e)).installation_key,installation);e.DB.close();
});
test('rendered settings script parses and removed update UI has no dangling calls',()=>{
 const html=renderPage();for(const match of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g))new Script(match[1]);
 assert.equal(html.includes('Update Rill'),false);assert.equal(html.includes('/api/updates/'),false);
 for(const name of ['adoptServerConfig','initial','statusText'])assert.match(html,new RegExp('function '+name+'\\('));
 assert.match(html,/id="setup-token"/);assert.match(html,/thirdParty.letterboxd/);
});

test('saved tracker markers preserve UI connection state and separate MAL credentials',()=>{
 const cfg=normalizeConfig({trackers:{trakt:{clientId:'id',clientSecret:'trakt-only',accessToken:'trakt-token',refreshToken:'refresh'},simkl:{clientId:'simkl',accessToken:'simkl-token'},mal:{clientId:'mal',clientSecret:'mal-only',accessToken:'mal-token'}}});
 const visible=publicConfig(cfg);for(const service of ['trakt','simkl','mal'])assert.equal(visible.trackers[service].accessToken,'__RILL_SAVED__');assert.equal(visible.trackers.trakt.refreshToken,'__RILL_SAVED__');
 const restored=mergePrivate(visible,cfg);assert.equal(restored.trackers.mal.clientSecret,'mal-only');assert.equal(restored.trackers.trakt.clientSecret,'trakt-only');
});
test('legacy owner username remains saveable without renaming',async()=>{
 const e=env();await ensureSchema(e.DB);const installation='b'.repeat(48);await claimOwner(e,installation,'John Smith Ω','old-password');const scope=(await sha256(installation)).slice(0,32);
 const cfg=normalizeConfig({installationKey:installation,jellyfin:{username:'John Smith Ω',password:''}});await e.DB.prepare('INSERT INTO accounts(scope,config,origin) VALUES(?,?,?)').bind(scope,Buffer.from(JSON.stringify(cfg)).toString('base64url'),origin).run();
 const login=await worker.fetch(req('/api/account/login',{username:'John Smith Ω',password:'old-password'}),e);assert.equal(login.status,200);const data=await login.json();
 const saved=await worker.fetch(req('/api/account/save',{config:{...data.config,name:'Updated name'}},login.headers.get('set-cookie').split(';')[0]),e);assert.equal(saved.status,200);assert.equal((await readOwner(e)).username,'John Smith Ω');e.DB.close();
});
test('provider artwork URLs are encrypted in image mappings and legacy caches purged',async()=>{
 const {imageTaggedJson,imageUrlByTag,artworkTag}=await import('../src/jellyfin/image-tags.ts');
 const e=env();await ensureSchema(e.DB);
 const url='https://api.ratingposterdb.com/private-rpdb-key/imdb/poster-default/tt123.jpg';const tag=artworkTag(url,e.RILL_DATA_KEY);
 await e.DB.prepare('INSERT INTO image_tags(tag,url,created) VALUES(?,?,?)').bind(tag,url,0).run();
 await e.DB.prepare('INSERT INTO presentations(key,value,expires) VALUES(?,?,?)').bind('legacy',JSON.stringify({ImageTags:{Primary:url}}),Date.now()+60000).run();
 await migrateSecrets(e);assert.equal((await e.DB.prepare('SELECT count(*) AS n FROM image_tags').first()).n,0);assert.equal((await e.DB.prepare('SELECT count(*) AS n FROM presentations').first()).n,0);
 const ctx={cfg:normalizeConfig({}),env:e,scope:'owner',cfgToken:'',origin,lang:'en',tmdbKey:undefined};const json=await imageTaggedJson(ctx,{ImageTags:{Primary:url}},(k,v)=>v);assert.equal(json.includes('private-rpdb-key'),false);
 const stored=await e.DB.prepare('SELECT url FROM image_tags').first();assert.match(stored.url,/^e1\./);assert.equal(stored.url.includes('private-rpdb-key'),false);assert.equal(await imageUrlByTag(ctx,tag),url);e.DB.close();
});

test('progressive delay admits a retry after its deadline, including concurrent attempts',async()=>{
 const e=env();await ensureSchema(e.DB);const original=Date.now;let now=original();Date.now=()=>now;
 try {
  const r=req('/login');for(let i=0;i<5;i++)assert.equal(await loginThrottle(e,r),0);
  assert.ok(await loginThrottle(e,r)>=1);now+=1001;assert.equal(await loginThrottle(e,r),0);
  const concurrent=await Promise.all(Array.from({length:5},()=>loginThrottle(e,r)));assert.ok(concurrent.every(n=>n>=2));
 }finally{Date.now=original;e.DB.close();}
});
test('MAL OAuth uses only MAL secret and saves tokens without returning them',async()=>{
 const e=env();const {cookie,data}=await setup(e);const cfg=data.config;
 cfg.trackers.trakt.clientSecret='trakt-only-secret';cfg.trackers.mal={clientId:'mal-id',clientSecret:'mal-only-secret',accessToken:'old-mal-token'};
 assert.equal((await worker.fetch(req('/api/account/save',{config:cfg},cookie),e)).status,200);
 const original=globalThis.fetch;let form;
 globalThis.fetch=async url=>{
  if(String(url).startsWith('https://cloudflare-dns.com/'))return new Response(JSON.stringify({Status:0,Answer:[{type:1,data:'8.8.8.8'}]}));
  assert.equal(String(url),'https://myanimelist.net/v1/oauth2/token');return new Response(JSON.stringify({access_token:'new-mal-token',refresh_token:'new-mal-refresh',expires_in:3600}));
 };
 // Capture only test fixture bodies; no real network or credentials.
 globalThis.fetch=((wrapped)=>async(url,init)=>{if(String(url).includes('myanimelist.net'))form=new URLSearchParams(init.body);return wrapped(url,init);})(globalThis.fetch);
 try {
  const res=await worker.fetch(req('/api/oauth/mal/token',{clientId:'mal-id',code:'test-code',verifier:'test-verifier'},cookie),e);assert.equal(res.status,200);const text=await res.text();assert.equal(text.includes('new-mal-token'),false);assert.equal(text.includes('new-mal-refresh'),false);assert.equal(form.get('client_secret'),'mal-only-secret');
 }finally{globalThis.fetch=original;e.DB.close();}
});

test('generated signing key is encrypted and isolated between D1 installations',async()=>{
 const {signingSecret}=await import('../src/jellyfin/auth.ts');
 const a=env(),b=env();delete a.RILL_SECRET;delete b.RILL_SECRET;await ensureSchema(a.DB);await ensureSchema(b.DB);
 const ctx=e=>({cfg:normalizeConfig({}),env:e,scope:'owner',cfgToken:'',origin,lang:'en',tmdbKey:undefined});
 const first=await signingSecret(ctx(a)),second=await signingSecret(ctx(b));assert.notEqual(first,second);assert.equal(await signingSecret(ctx(a)),first);
 assert.match((await a.DB.prepare("SELECT value FROM state WHERE key='install:signing-key'").first()).value,/^e1\./);a.DB.close();b.DB.close();
});
