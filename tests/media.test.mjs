import {test} from 'node:test';
import assert from 'node:assert/strict';
import {imageResponse} from '../src/jellyfin/images.ts';
import {fetchJson} from '../src/util/cache.ts';
import {IMAGE_LIMIT} from '../src/security/limits.ts';
const png=Uint8Array.from([137,80,78,71,13,10,26,10,0,0,0,0]);
async function mocked(upstream,work){
 const original=globalThis.fetch;const originalCaches=globalThis.caches;
 globalThis.caches={default:{match:async()=>undefined,put:async()=>{}}};
 globalThis.fetch=async url=>String(url).startsWith('https://cloudflare-dns.com/')?new Response(JSON.stringify({Status:0,Answer:[{type:1,data:'8.8.8.8'}]})):upstream();
 try{return await work();}finally{globalThis.fetch=original;globalThis.caches=originalCaches;}
}
const request=new Request('https://rill.example/Items/id/Images/Primary');
const jf={ctx:{origin:'https://rill.example',scope:'owner'},q:()=>undefined};
test('proxy rejects SVG, spoofed MIME, video and oversized images; raster gets defensive headers',async()=>{
 for(const [mime,body] of [['image/svg+xml','<svg/>'],['image/png','<svg/>'],['video/mp4',png]])await mocked(()=>new Response(body,{headers:{'content-type':mime}}),async()=>assert.equal((await imageResponse(jf,request,'https://art.example/image','primary')).status,502));
 await mocked(()=>new Response(png,{headers:{'content-type':'image/png'}}),async()=>{
  const res=await imageResponse(jf,request,'https://art.example/image','primary');assert.equal(res.status,200);assert.equal(res.headers.get('content-security-policy'),'sandbox');assert.equal(res.headers.get('x-content-type-options'),'nosniff');assert.equal(res.headers.get('content-disposition'),'inline');assert.deepEqual(new Uint8Array(await res.arrayBuffer()),png);
 });
 await mocked(()=>new Response(new ReadableStream({start(c){c.enqueue(png);c.enqueue(new Uint8Array(IMAGE_LIMIT));c.close();}}),{headers:{'content-type':'image/png'}}),async()=>assert.equal((await imageResponse(jf,request,'https://art.example/image','primary')).status,502));
});
test('upstream JSON is byte limited before parsing even without Content-Length',async()=>{
 await mocked(()=>new Response(JSON.stringify({data:'x'.repeat(5*1024*1024)})),async()=>assert.equal(await fetchJson('https://api.example/json'),null));
 await mocked(()=>new Response('{"ok":true}'),async()=>assert.deepEqual(await fetchJson('https://api.example/json'),{ok:true}));
});

test('HTTP exception is opt-in and limited to add-on requests, including background work',async()=>{
 const {withOutboundPolicy}=await import('../src/security/outbound.ts');
 await mocked(()=>new Response('{"ok":true}'),async()=>{
  assert.equal(await fetchJson('http://addon.example/json',{addon:true}),null);
  await withOutboundPolicy({ALLOW_HTTP_ADDONS:'true'},async()=>{
   assert.deepEqual(await fetchJson('http://addon.example/json',{addon:true}),{ok:true});
   assert.equal(await fetchJson('http://addon.example/json'),null);
  });
 });
});
