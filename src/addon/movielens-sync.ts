import type { Ctx } from '../context';
import { fetchJson } from '../util/cache';
import { sha256 } from '../util/bytes';
import { credentials } from '../storage/credentials';
import { stateGet,statePut } from '../storage/state';
import { cleanupDatabase } from '../storage/budget';
import { movieLensRead } from './movielens';

interface Rating {imdb:string;rating:number;at:string;title:string;year?:number}
interface RatingRow {
  rating?:number;user_rating?:number;rated_at?:string;user_rated_at?:string;last_watched_at?:string;anime_type?:string;
  movie?:{title?:string;year?:number;ids?:{imdb?:string}};
  show?:{title?:string;year?:number;ids?:{imdb?:string}};
}
export interface MovieLensSyncStatus {checkedAt:string;nextAt:number;fingerprint?:string;sent:number;successCount?:number;alreadyRatedCount?:number;errorCount?:number;error?:string}
const HEADER=['Const','Your Rating','Date Rated','Title','URL','Title Type','IMDb Rating','Runtime (mins)','Year','Genres','Num Votes','Release Date','Directors'];
const csvCell=(value:unknown)=>'"'+String(value??'').replace(/"/g,'""')+'"';
export function normalizeRatings(groups:RatingRow[][]):Rating[] {
  const result=new Map<string,Rating>();
  for(const rows of groups)for(const row of rows) {
    if(row.anime_type&&!['movie','ona'].includes(row.anime_type.toLowerCase()))continue;
    const media=row.movie??row.show,rating=row.user_rating??row.rating;
    if(!media||typeof rating!=='number'||!Number.isFinite(rating)||rating<1||rating>10)continue;
    const timestamp=row.user_rated_at??row.rated_at??row.last_watched_at??'';
    const at=Number.isFinite(Date.parse(timestamp))?new Date(timestamp).toISOString():'';
    for(const part of String(media.ids?.imdb??'').split(/[,\s]+/)) {
      const match=/^(?:tt)?(\d{5,10})$/.exec(part);if(!match)continue;
      const imdb=`tt${match[1]}`,old=result.get(imdb);
      if(!old||at>old.at)result.set(imdb,{imdb,rating,at,title:media.title??'',year:media.year});
    }
  }
  return [...result.values()].sort((a,b)=>a.imdb.localeCompare(b.imdb));
}
export function ratingsCsv(rows:Rating[]):string {
  return [HEADER.join(','),...rows.map(r=>[r.imdb,r.rating,r.at.slice(0,10),r.title,`https://www.imdb.com/title/${r.imdb}/`,'movie','','',r.year,'','','',''].map(csvCell).join(','))].join('\r\n');
}
async function read<T>(ctx:Ctx,url:string,headers:Record<string,string>={}):Promise<T> {
  const value=await fetchJson<T>(url,{headers,ttl:60,cacheScope:ctx.scope});
  if(value===null)throw new Error('A rating service is unavailable; nothing was imported');
  return value;
}
async function collect(ctx:Ctx):Promise<Rating[]> {
  const groups:RatingRow[][]=[];
  const trakt=ctx.cfg.trackers.trakt;
  if(trakt?.accessToken&&trakt.clientId) {
    const auth=await credentials(ctx,'trakt',trakt);
    groups.push(await read(ctx,'https://api.trakt.tv/sync/ratings/movies',{'trakt-api-version':'2','trakt-api-key':auth.clientId,authorization:`Bearer ${auth.accessToken}`}));
  }
  const simkl=ctx.cfg.trackers.simkl;
  if(simkl?.accessToken&&simkl.clientId)for(const type of ['movies','anime'])groups.push(await read(ctx,`https://api.simkl.com/sync/ratings/${type}`,{'simkl-api-key':simkl.clientId,authorization:`Bearer ${simkl.accessToken}`}));
  if(ctx.cfg.keys.mdblist) {
    let cursor:string|undefined;const seen=new Set<string>();let complete=false;
    for(let page=0;page<100;page++) {
      const url=new URL('https://api.mdblist.com/sync/ratings');url.searchParams.set('apikey',ctx.cfg.keys.mdblist);url.searchParams.set('limit','1000');if(cursor)url.searchParams.set('cursor',cursor);
      const data=await read<{movies?:RatingRow[];pagination?:{next_cursor?:string}}>(ctx,url.href);
      groups.push(data.movies??[]);cursor=data.pagination?.next_cursor;
      if(!cursor){complete=true;break;}
      if(seen.has(cursor))throw new Error('MDBList repeated a ratings page; nothing was imported');seen.add(cursor);
    }
    if(!complete)throw new Error('The rating import limit was reached; nothing was imported');
  }
  return normalizeRatings(groups);
}
export async function importRatingsCsv(ctx:Ctx,csv:string):Promise<Pick<MovieLensSyncStatus,'successCount'|'alreadyRatedCount'|'errorCount'>> {
  if(csv.length>5_000_000)throw new Error('Rating file exceeds 5 MB');
  if(!/^"?Const"?,"?Your Rating"?,/.test(csv.replace(/^\uFEFF/,'')))throw new Error('Choose an IMDb ratings CSV file');
  const form=new FormData();form.append('file',new Blob([csv],{type:'text/csv'}),'ratings.csv');
  const data=await movieLensRead<{successCount?:number;alreadyRatedCount?:number;errorCount?:number}>(ctx,'actions/imdb-import',{method:'POST',headers:{referer:'https://movielens.org/profile/settings/import-export'},body:form});
  if(!Number.isFinite(data?.successCount)||!Number.isFinite(data?.alreadyRatedCount)||!Number.isFinite(data?.errorCount))throw new Error('MovieLens did not confirm the import');
  return{successCount:data.successCount,alreadyRatedCount:data.alreadyRatedCount,errorCount:data.errorCount};
}
async function syncKey(ctx:Ctx):Promise<string>{return `movielens-sync:v1:${ctx.scope}:${(await sha256(ctx.cfg.movieLens?.username??'')).slice(0,24)}`;}
export async function movieLensSyncStatus(ctx:Ctx):Promise<MovieLensSyncStatus|null>{return stateGet(ctx,await syncKey(ctx));}
export async function syncMovieLens(ctx:Ctx,manual=false):Promise<MovieLensSyncStatus|null> {
  if(ctx.profile&&!ctx.profile.sharesHistory)return null;
  if(!ctx.cfg.movieLens?.username||!ctx.cfg.movieLens.password||!manual&&!ctx.cfg.movieLens.syncRatings)return null;
  const db=ctx.env.DB;if(!db)throw new Error('Rating sync requires durable storage');
  const key=await syncKey(ctx),owner=crypto.randomUUID(),lock=`${key}:lock`,now=Date.now();
  const previous=await stateGet<MovieLensSyncStatus>(ctx,key);
  if(!manual&&previous&&previous.nextAt>now)return previous;
  const claim=await db.prepare('INSERT INTO state(key,value,expires) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,expires=excluded.expires WHERE state.expires<=? RETURNING key').bind(lock,owner,now+300_000,now).first();
  if(!claim)throw new Error('MovieLens synchronization is already running');
  try {
    const rows=await collect(ctx),fingerprint=await sha256(JSON.stringify(rows.map(r=>[r.imdb,r.rating])));
    const result=rows.length&&fingerprint!==previous?.fingerprint?await importRatingsCsv(ctx,ratingsCsv(rows)):{};
    const status:MovieLensSyncStatus={checkedAt:new Date().toISOString(),nextAt:now+86400_000,fingerprint,sent:fingerprint===previous?.fingerprint?0:rows.length,...result};
    await statePut(ctx,key,status,365*86400);return status;
  }catch(error){
    await statePut({...ctx,env:{...ctx.env,DB:cleanupDatabase(db)}},key,{...previous,checkedAt:new Date().toISOString(),nextAt:now+3600_000,sent:0,error:'MovieLens import failed'},365*86400);
    throw error;
  }finally{await cleanupDatabase(db).prepare('DELETE FROM state WHERE key=? AND value=?').bind(lock,owner).run();}
}
