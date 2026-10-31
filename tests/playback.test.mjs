import {test} from 'node:test';
import assert from 'node:assert/strict';
import {D1} from './d1.mjs';
import worker from '../src/index.ts';
import {normalizeConfig} from '../src/config/schema.ts';
import {safeFetch,forgetResolvedHosts} from '../src/security/outbound.ts';
import {preparePresentation,presentationRevision} from '../src/jellyfin/presentation.ts';

const origin='https://rill.example';
const HASH='0123456789abcdef0123456789abcdef01234567';
const DIRECT='https://cdn.example/private-debrid-key/movie.mkv';
const AUTH='MediaBrowser Client="test", Device="test", DeviceId="test-device", Version="1"';

function addon(kind){
 const metas=Array.from({length:16},(_,i)=>({id:`tt${9000000+i}`,type:'movie',name:`Movie ${i}`,poster:'https://img.example/p.jpg'}));
 return url=>{
  const path=new URL(url).pathname.split('/').slice(2).join('/');
  if(path==='manifest.json')return Response.json({id:`test.${kind}`,version:'1.0.0',name:kind,resources:['catalog','meta','stream'],types:['movie','series'],idPrefixes:['tt'],catalogs:[{type:'movie',id:'films',name:'Films'}]});
  if(path.startsWith('catalog/movie/films'))return Response.json({metas});
  const meta=/^meta\/movie\/(tt\d+)\.json$/.exec(path);
  if(meta)return Response.json({meta:{...metas.find(m=>m.id===meta[1]),description:'Test film',runtime:'90 min',cast:['Someone']}});
  if(path.startsWith('stream/'))return Response.json({streams:kind==='torrent'
   ?[{name:'Torrent',title:'film.mkv',infoHash:HASH,fileIdx:2,sources:['tracker:udp://tracker.example:1337/announce'],behaviorHints:{filename:'film.mkv'}}]
   :kind==='headers'?[{name:'Proxy',url:DIRECT,behaviorHints:{proxyHeaders:{request:{referer:'https://site.example'}}}}]
   :[{name:'Direct',title:'film.mkv',url:DIRECT,behaviorHints:{filename:'film.mkv'}}]});
  return new Response('not found',{status:404});
 };
}

async function withNetwork(kind,work){
 const original=globalThis.fetch,originalCaches=globalThis.caches;const calls={dns:0,addon:0};
 globalThis.caches={default:{match:async()=>undefined,put:async()=>{},delete:async()=>{}}};
 globalThis.fetch=async input=>{
  const url=String(typeof input==='string'?input:input.url);
  if(url.startsWith('https://cloudflare-dns.com/')){calls.dns++;return Response.json({Status:0,Answer:url.includes('type=A&')||url.endsWith('type=A')?[{type:1,data:'93.184.215.14',TTL:300}]:[]});}
  calls.addon++;return addon(kind)(url);
 };
 forgetResolvedHosts();
 try{return await work(calls);}finally{globalThis.fetch=original;globalThis.caches=originalCaches;}
}

async function server(kind,extra={}){
 const sent=[];
 const e={DB:new D1(),RILL_DATA_KEY:Buffer.alloc(32,5).toString('base64'),RILL_SETUP_TOKEN:'0123456789abcdef0123456789abcdef',RILL_SECRET:'test-signing-key',
  RILL_JOBS:{send:async body=>sent.push(body),sendBatch:async messages=>sent.push(...messages.map(m=>m.body))}};
 const pending=[];const exec={waitUntil:p=>pending.push(p),passThroughOnException(){}};
 const call=async(path,init={})=>{const res=await worker.fetch(new Request(origin+path,init),e,exec);await Promise.allSettled(pending.splice(0));return res;};
 const url=`https://addon.example/${kind}/manifest.json`;
 const save=await call('/api/account/save',{method:'POST',headers:{origin,'content-type':'application/json','cf-connecting-ip':'203.0.113.7'},
  body:JSON.stringify({setupToken:e.RILL_SETUP_TOKEN,config:{jellyfin:{username:'owner',password:'correct-horse-battery',...extra},addons:{catalog:[url],meta:[],stream:[url],subtitle:[]}}})});
 assert.equal(save.status,200);
 const cookie=save.headers.get('set-cookie').split(';')[0];const saved=await save.json();
 const login=await (await call('/Users/AuthenticateByName',{method:'POST',headers:{'content-type':'application/json','x-emby-authorization':AUTH},body:JSON.stringify({Username:'owner',Pw:'correct-horse-battery'})})).json();
 const headers={'x-emby-authorization':`${AUTH}, Token="${login.AccessToken}"`};
 const views=await (await call(`/Users/${login.User.Id}/Views`,{headers})).json();
 const firstMovie=async()=>(await (await call(`/Users/${login.User.Id}/Items?ParentId=${views.Items[0].Id}&Limit=1&Recursive=true`,{headers})).json()).Items[0].Id;
 return {e,sent,call,cookie,saved,headers,uid:login.User.Id,token:login.AccessToken,views:views.Items,firstMovie};
}
const playbackInfo=(s,id)=>s.call(`/Items/${id}/PlaybackInfo?UserId=${s.uid}`,{method:'POST',headers:{...s.headers,'content-type':'application/json'},body:'{}'});

test('torrent-only add-ons explain NoCompatibleStream; a streaming server makes them playable',()=>withNetwork('torrent',async()=>{
 const warn=console.warn;const logged=[];console.warn=(...a)=>logged.push(JSON.stringify(a));
 try{
  const s=await server('torrent');const id=await s.firstMovie();
  const none=await (await playbackInfo(s,id)).json();
  assert.equal(none.ErrorCode,'NoCompatibleStream');assert.equal(none.MediaSources.length,0);
  const line=logged.find(l=>l.includes('No playable stream'));assert.ok(line);assert.match(line,/"torrentOnly":1/);assert.equal(line.includes(HASH),false);
  assert.equal((await s.call(`/Videos/${id}/stream?static=true`,{headers:s.headers})).status,404);
  s.e.DB.close();
  const t=await server('torrent',{torrentServer:'http://192.168.1.10:11470/'});const tid=await t.firstMovie();
  const info=await (await playbackInfo(t,tid)).json();
  assert.equal(info.ErrorCode,undefined);assert.equal(info.MediaSources.length,1);
  const expected=`http://192.168.1.10:11470/${HASH}/2?tr=${encodeURIComponent('tracker:udp://tracker.example:1337/announce')}`;
  assert.equal(info.MediaSources[0].Path,expected);assert.equal(info.MediaSources[0].Container,'mkv');
  const redirect=await t.call(`/Videos/${tid}/stream?static=true&MediaSourceId=${info.MediaSources[0].Id}`,{headers:t.headers,redirect:'manual'});
  assert.equal(redirect.status,302);assert.equal(redirect.headers.get('location'),expected);
  t.e.DB.close();
 }finally{console.warn=warn;}
}));

test('streams that need proxy headers are counted, not offered',()=>withNetwork('headers',async()=>{
 const warn=console.warn;const logged=[];console.warn=(...a)=>logged.push(JSON.stringify(a));
 try{
  const s=await server('headers');const info=await (await playbackInfo(s,await s.firstMovie())).json();
  assert.equal(info.ErrorCode,'NoCompatibleStream');
  const line=logged.find(l=>l.includes('No playable stream'));assert.match(line,/"needsHeaders":1/);assert.equal(line.includes('private-debrid-key'),false);
  s.e.DB.close();
 }finally{console.warn=warn;}
}));

test('item pages expose an absolute placeholder source that resolves on play',()=>withNetwork('direct',async()=>{
 const s=await server('direct');const id=await s.firstMovie();
 const item=await (await s.call(`/Users/${s.uid}/Items/${id}`,{headers:s.headers})).json();
 const source=item.MediaSources[0];
 assert.equal(source.Type,'Default');assert.ok(source.Path.startsWith(`${origin}/Videos/`),source.Path);assert.match(source.Path,/[?&]api_key=/);
 const res=await s.call(source.Path.slice(origin.length),{redirect:'manual'});
 assert.equal(res.status,302);assert.equal(res.headers.get('location'),DIRECT);
 const info=await (await playbackInfo(s,id)).json();assert.equal(info.MediaSources[0].Path,DIRECT);
 const download=await s.call(`/Items/${id}/Download?api_key=${s.token}`,{redirect:'manual'});assert.equal(download.status,302);assert.equal(download.headers.get('location'),DIRECT);
 s.e.DB.close();
}));

test('BitrateTest answers with the requested size, capped, signed-in only',()=>withNetwork('direct',async()=>{
 const s=await server('direct');
 const res=await s.call('/Playback/BitrateTest?Size=500000',{headers:s.headers});
 assert.equal(res.status,200);assert.equal((await res.arrayBuffer()).byteLength,500000);
 assert.equal((await (await s.call('/Playback/BitrateTest?Size=999999999',{headers:s.headers})).arrayBuffer()).byteLength,10_000_000);
 assert.equal((await s.call('/Playback/BitrateTest?Size=10')).status,401);
 s.e.DB.close();
}));

test('validated DNS answers are reused; private answers never are',async()=>{
 const original=globalThis.fetch;let dns=0;let answer='93.184.215.14';
 globalThis.fetch=async url=>{if(String(url).startsWith('https://cloudflare-dns.com/')){dns++;return Response.json({Status:0,Answer:String(url).endsWith('type=A')?[{type:1,data:answer,TTL:60}]:[]});}return new Response('ok');};
 forgetResolvedHosts();
 try{
  for(let i=0;i<3;i++)assert.equal(await (await safeFetch('https://addon.example/a')).text(),'ok');
  assert.equal(dns,2);
  answer='10.0.0.5';
  for(let i=0;i<2;i++)await assert.rejects(safeFetch('https://private.example/a'));
  assert.equal(dns,6);
 }finally{globalThis.fetch=original;forgetResolvedHosts();}
});

test('one home screen queues a few batched presentation jobs, once',()=>withNetwork('direct',async()=>{
 const s=await server('direct');
 const latest=()=>s.call(`/Users/${s.uid}/Items/Latest?ParentId=${s.views[0].Id}&Limit=16`,{headers:s.headers});
 assert.equal((await latest()).status,200);
 assert.equal(s.sent.length,2);assert.ok(s.sent.every(job=>job.kind==='presentation'&&job.ids.length===8));
 for(const job of s.sent.splice(0))await preparePresentation(job,s.e);
 assert.equal((await s.e.DB.prepare("SELECT count(*) AS n FROM presentations WHERE value!='null'").first()).n,16);
 const items=await (await latest()).json();
 assert.equal(s.sent.length,0);assert.equal(items[0].Overview,'Test film');
 s.e.DB.close();
}));

test('presentation keys ignore settings that do not change metadata',async()=>{
 const cfg=normalizeConfig({addons:{meta:['https://addon.example/a/manifest.json']}});
 const refreshed=normalizeConfig({...cfg,trackers:{...cfg.trackers,trakt:{clientId:'id',accessToken:'rotated'}},jellyfin:{...cfg.jellyfin,maxSources:5}});
 const other=normalizeConfig({...cfg,addons:{...cfg.addons,meta:['https://addon.example/b/manifest.json']}});
 assert.equal(await presentationRevision(cfg),await presentationRevision(refreshed));
 assert.notEqual(await presentationRevision(cfg),await presentationRevision(other));
});

test('torrent server setting accepts only plain http(s) addresses',()=>{
 assert.equal(normalizeConfig({jellyfin:{torrentServer:'http://192.168.1.10:11470/'}}).jellyfin.torrentServer,'http://192.168.1.10:11470');
 assert.equal(normalizeConfig({jellyfin:{torrentServer:'https://stremio.example/server'}}).jellyfin.torrentServer,'https://stremio.example/server');
 for(const bad of ['ftp://x.example','http://user:pw@x.example','javascript:alert(1)','http://x.example/?a=b',''])assert.equal('torrentServer' in normalizeConfig({jellyfin:{torrentServer:bad}}).jellyfin,false,bad);
 assert.equal(JSON.stringify(normalizeConfig({})).includes('torrentServer'),false);
});

test('settings stream check reports counts without stream URLs',()=>withNetwork('torrent',async()=>{
 const s=await server('torrent');
 const res=await s.call('/api/probe',{method:'POST',headers:{origin,'content-type':'application/json',cookie:s.cookie},body:JSON.stringify({url:'https://addon.example/torrent/manifest.json',type:'movie',id:'tt9000001'})});
 assert.equal(res.status,200);const text=await res.text();const data=JSON.parse(text);
 assert.deepEqual(data.streams,{addons:1,asked:1,failed:0,streams:1,playable:0,torrentOnly:1,needsHeaders:0,other:0});
 assert.equal(text.includes(HASH),false);
 s.e.DB.close();
}));
