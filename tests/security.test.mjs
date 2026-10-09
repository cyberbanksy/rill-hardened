import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validateDestination, safeFetch} from '../src/security/outbound.ts';
import {readLimited, rasterType} from '../src/security/limits.ts';
import {seal,unseal} from '../src/security/secrets.ts';
import {encodeConfig,decodeConfig} from '../src/config/codec.ts';
import {normalizeConfig} from '../src/config/schema.ts';

test('reject private, reserved, ambiguous and credentialed destinations',()=>{
 for(const url of ['http://example.com','https://localhost','https://LOCALHOST.','https://foo.local','https://127.1','https://2130706433','https://10.0.0.1','https://169.254.169.254','https://192.168.0.1','https://100.64.0.1','https://198.18.0.1','https://[::1]','https://[::ffff:7f00:1]','https://[fc00::1]','https://user:pass@example.com']) assert.throws(()=>validateDestination(url));
 assert.equal(validateDestination('https://example.com/a').hostname,'example.com');
 assert.equal(validateDestination('http://example.com',{allowHttp:true}).protocol,'http:');
});
test('stream limits without content length',async()=>{
 const stream=new ReadableStream({start(c){c.enqueue(new Uint8Array(4));c.enqueue(new Uint8Array(5));c.close();}});
 await assert.rejects(readLimited(stream,8));
 assert.equal((await readLimited(new Response('ok').body,8)).length,2);
});
test('raster MIME and magic must agree',()=>{
 assert.equal(rasterType('image/png',Uint8Array.from([137,80,78,71,13,10,26,10])), 'image/png');
 assert.equal(rasterType('image/svg+xml',new TextEncoder().encode('<svg/>')),null);
 assert.equal(rasterType('image/png',new TextEncoder().encode('<svg/>')),null);
 assert.equal(rasterType('text/html',Uint8Array.from([255,216,255])),null);
});
test('manual redirect validation and DNS checks precede fetch',async()=>{
 let calls=0;
 await assert.rejects(safeFetch('https://public.example',{}, {resolve:async()=>['8.8.8.8'],fetcher:async()=>{calls++;return new Response(null,{status:302,headers:{location:'https://127.0.0.1'}});}}));
 assert.equal(calls,1);
 await assert.rejects(safeFetch('https://public.example',{}, {resolve:async()=>['10.0.0.2'],fetcher:async()=>{throw Error('must not fetch');}}));
});
test('AES-GCM authentication and fresh nonces',async()=>{
 const env={RILL_DATA_KEY:Buffer.alloc(32,7).toString('base64')};
 const a=await seal('credential',env,'scope'),b=await seal('credential',env,'scope');
 assert.notEqual(a,b); assert.equal(await unseal(a,env,'scope'),'credential');
 await assert.rejects(unseal(a,env,'other')); await assert.rejects(seal('secret',{},'scope'));
});
test('codec bounds decompression and never serializes owner password',async()=>{
 const cfg=normalizeConfig({jellyfin:{username:'owner',password:'secret-password'}});
 const token=await encodeConfig(cfg);
 assert.equal((await decodeConfig(token)).jellyfin.password,'');
 assert.equal(await decodeConfig('x'.repeat(65537)),null);
 const ds=new CompressionStream('deflate-raw');
 const writer=ds.writable.getWriter();void writer.write(new TextEncoder().encode(JSON.stringify({name:'x'.repeat(300000)})));void writer.close();
 const bytes=new Uint8Array(await new Response(ds.readable).arrayBuffer());
 assert.equal(await decodeConfig('c1.'+Buffer.from(bytes).toString('base64url')),null);
});

test('AI keys/search flags and saved Letterboxd lists do not bypass explicit opt-in',async()=>{
 const {generate}=await import('../src/addon/recommendations.ts');
 const {aiQuery}=await import('../src/addon/ai.ts');
 const {sourceDefinitions,sourceItems}=await import('../src/addon/sources.ts');
 const cfg=normalizeConfig({recommendations:{apiKey:'test-key',model:'test-model',aiSearch:true},lists:{letterboxd:['private-list']}});
 assert.equal(cfg.recommendations.enabled,false);assert.equal(cfg.thirdParty.letterboxd,false);
 const ctx={cfg,env:{},scope:'owner',cfgToken:'',origin:'https://rill.example',lang:'en',tmdbKey:undefined};
 assert.equal(aiQuery(ctx,'ai: test'),null);await assert.rejects(generate(cfg.recommendations,'test'),/Enable AI/);
 const original=globalThis.fetch;globalThis.fetch=async()=>{assert.fail('Disabled third party attempted network');};
 try {assert.equal((await sourceDefinitions(ctx)).some(d=>d.id.startsWith('letterboxd.')),false);assert.deepEqual(await sourceItems(ctx,'movie','letterboxd.0',{}),[]);}
 finally{globalThis.fetch=original;}
});
test('built-in DNS check uses a redirect mode Workers accept',async()=>{
 // Workers throw on redirect:'error', which once broke every add-on fetch while mocked tests passed.
 const real=globalThis.fetch, modes=[];
 globalThis.fetch=async(url,init={})=>{
  if(init.redirect==='error') throw TypeError('Invalid redirect value');
  modes.push(init.redirect);
  if(String(url).startsWith('https://cloudflare-dns.com/')) return Response.json({Status:0,Answer:[{type:1,data:'8.8.8.8'}]});
  return Response.json({ok:true});
 };
 try{
  const res=await safeFetch('https://public.example/manifest.json');
  assert.deepEqual(await res.json(),{ok:true});
  assert.ok(modes.every(m=>m==='manual'));
 }finally{globalThis.fetch=real;}
});
