import type { Ctx } from '../context';
import { loadConfig,storeConfig,migrateSecrets } from '../security/secrets';
import { sha256 } from '../util/bytes';
import { registerAccount } from './state';
import { recommendationItems } from '../addon/recommendations';
import { cleanupDatabase } from './budget';

interface Job {id:string;status:'pending'|'done'|'failed';position:number;counts:Record<string,number>;error?:string;created:number;updated:number}
export async function recommendationJob(ctx:Ctx,id?:string):Promise<Job|null> {
  const row=await ctx.env.DB?.prepare(`SELECT id,status,position,counts,error,created,updated FROM recommendation_jobs WHERE scope=? ${id?'AND id=?':''} ORDER BY created DESC,rowid DESC LIMIT 1`).bind(...(id?[ctx.scope,id]:[ctx.scope])).first<Omit<Job,'counts'>&{counts:string}>();
  return row?{...row,counts:JSON.parse(row.counts)}:null;
}
export async function queueRecommendations(ctx:Ctx,rebuild=false):Promise<Job> {
  const db=ctx.env.DB;if(!db)throw new Error('Connect durable storage first');
  await registerAccount(ctx);
  const id=crypto.randomUUID(),now=Date.now();
  const statements=[db.prepare("INSERT OR IGNORE INTO recommendation_jobs(id,scope,config,origin,created,updated) VALUES(?,?,?,?,?,?)").bind(id,ctx.scope,await storeConfig(ctx.cfg,ctx.env,ctx.scope),ctx.origin,now,now)];
  if(rebuild)statements.push(db.prepare('DELETE FROM state WHERE ((key>=? AND key<?) OR (key>=? AND key<?)) AND EXISTS(SELECT 1 FROM recommendation_jobs WHERE id=?)').bind(`taste:v1:${ctx.scope}:`,`taste:v1:${ctx.scope};`,`recommendations:v1:${ctx.scope}:`,`recommendations:v1:${ctx.scope};`,id));
  const [inserted]=await db.batch(statements);
  if(!inserted.meta.changes) {
    const active=await db.prepare("SELECT id FROM recommendation_jobs WHERE scope=? AND status='pending'").bind(ctx.scope).first<{id:string}>();
    if(!active)throw new Error('Recommendation job changed; try again');
    return (await recommendationJob(ctx,active.id))!;
  }
  return (await recommendationJob(ctx,id))!;
}
export async function advanceRecommendations(ctx:Ctx):Promise<boolean> {
  const db=ctx.env.DB;if(!db)return false;
  const owner=crypto.randomUUID(),now=Date.now();
  const job=await db.prepare("UPDATE recommendation_jobs SET lease=?,lease_until=?,updated=? WHERE id=(SELECT id FROM recommendation_jobs WHERE scope=? AND status='pending' AND lease_until<=? ORDER BY created LIMIT 1) RETURNING id,config,origin,position,counts").bind(owner,now+600_000,now,ctx.scope,now).first<{id:string;config:string;origin:string;position:number;counts:string}>();
  if(!job)return false;
  try {
    const cfg=await loadConfig(job.config,ctx.env,ctx.scope);if(!cfg)throw new Error('Saved recommendation settings are invalid');
    const request:Ctx={...ctx,cfg,cfgToken:job.config,origin:job.origin,lang:cfg.language.slice(0,2),tmdbKey:cfg.keys.tmdb||ctx.env.TMDB_KEY,cacheRevision:(await sha256(JSON.stringify(cfg))).slice(0,16)};
    const kind=(['movie','series','anime'] as const)[job.position];
    if(!kind)throw new Error('Invalid recommendation job position');
    const count=(await recommendationItems(request,kind,0)).length,counts={...JSON.parse(job.counts),[kind]:count};
    await db.prepare('UPDATE recommendation_jobs SET position=?,counts=?,status=?,updated=? WHERE id=? AND lease=?').bind(job.position+1,JSON.stringify(counts),job.position===2?'done':'pending',Date.now(),job.id,owner).run();
  }catch(error){
    await cleanupDatabase(db).prepare("UPDATE recommendation_jobs SET status='failed',error=?,updated=? WHERE id=? AND lease=?").bind('Recommendation generation failed',Date.now(),job.id,owner).run();
  }finally{await cleanupDatabase(db).prepare('UPDATE recommendation_jobs SET lease=NULL,lease_until=0 WHERE id=? AND lease=?').bind(job.id,owner).run();}
  return true;
}
