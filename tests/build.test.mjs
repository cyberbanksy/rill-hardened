import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {prepareBuild,preparedBuild} from '../scripts/build.mjs';

test('build runs local compiler and tests only, and deployment refuses changed inputs',()=>{
 const root=mkdtempSync(join(import.meta.dirname,'build-fixture-'));
 try {
  for(const dir of ['src','scripts','migrations','tests','node_modules/typescript/bin'])mkdirSync(join(root,dir),{recursive:true});
  for(const file of ['package.json','package-lock.json','tsconfig.json','wrangler.jsonc','node_modules/typescript/bin/tsc'])writeFileSync(join(root,file),'{}');
  writeFileSync(join(root,'src/worker.ts'),'reviewed local source');writeFileSync(join(root,'tests/check.test.mjs'),'');
  const calls=[];const result=prepareBuild({root,execute:(cmd,args,cwd)=>calls.push({cmd,args,cwd})});
  assert.equal(result.destination,root);assert.equal(calls.length,2);
  for(const call of calls){assert.equal(call.cwd,root);assert.equal(call.cmd,process.execPath);assert.equal(call.args.some(arg=>/clone|npm|upstream|deploy/.test(arg)),false);}
  assert.equal(preparedBuild(root).digest,result.digest);
  writeFileSync(join(root,'src/worker.ts'),'changed local source');assert.throws(()=>preparedBuild(root),/rebuild/);
  assert.throws(()=>prepareBuild({root,execute:()=>{throw Error('compile failed');}}));assert.throws(()=>preparedBuild(root),/Run npm run build/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
