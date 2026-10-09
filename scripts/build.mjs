import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
export function run(command,args,cwd) { execFileSync(command,args,{cwd,stdio:'inherit',env:{...process.env,WRANGLER_SEND_METRICS:'false'}}); }
export function sourceDigest(root) {
  const hash=createHash('sha256');
  function add(path) {
    for(const entry of readdirSync(join(root,path),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
      const name=join(path,entry.name);
      if(entry.isSymbolicLink()) throw Error('Build inputs must not be symlinks');
      if(entry.isDirectory()) add(name);else {hash.update(name);hash.update(readFileSync(join(root,name)));}
    }
  }
  for(const dir of ['src','scripts','migrations','tests']) add(dir);
  for(const file of ['package.json','package-lock.json','tsconfig.json','wrangler.jsonc']) {hash.update(file);hash.update(readFileSync(join(root,file)));}
  return hash.digest('hex');
}
export function prepareBuild({root=process.cwd(),execute=run}={}) {
  const marker=join(root,'.rill-ready.json');rmSync(marker,{force:true});
  if(!existsSync(join(root,'node_modules/typescript/bin/tsc'))) throw Error('Install reviewed dependencies with npm ci --ignore-scripts first.');
  execute(process.execPath,[join(root,'node_modules/typescript/bin/tsc'),'--noEmit'],root);
  execute(process.execPath,['--import',join(root,'tests/register.mjs'),'--test',...readdirSync(join(root,'tests')).filter(f=>f.endsWith('.test.mjs')).map(f=>join(root,'tests',f))],root);
  const digest=sourceDigest(root);writeFileSync(marker,JSON.stringify({digest}));return {destination:root,digest};
}
export function preparedBuild(root=process.cwd()) {
  const marker=join(root,'.rill-ready.json');
  if(!existsSync(marker)) throw Error('Run npm run build before deploying.');
  const {digest}=JSON.parse(readFileSync(marker,'utf8'));
  if(digest!==sourceDigest(root)) throw Error('Working tree changed; rebuild before deploying.');
  return {destination:root,digest};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try {prepareBuild();}catch {console.error('Local build failed.');process.exitCode=1;}
}
