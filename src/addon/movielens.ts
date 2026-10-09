import {seal,unseal} from '../security/secrets';
import {limitedJson,limitedText} from '../security/limits';
import {safeFetch,addonHttpAllowed} from '../security/outbound';
import type { Ctx } from '../context';
import type { ContentType, MetaPreview } from '../stremio/types';
import type { CatalogDefinition, CatalogExtra } from './catalogs';
import { stateGet, statePut, stateDelete } from '../storage/state';
import { sha256 } from '../util/bytes';
import { memo } from '../util/cache';
import { sourcePreview } from './sources';
import { mapLimit } from '../util/concurrency';

const API='https://movielens.org/api';
interface MovieRow { movie?: { title?:string; tmdbMovieId?:number; imdbMovieId?:string } }
async function sessionKey(ctx:Ctx):Promise<string> {
  return `movielens:session:${ctx.scope}:${await sha256(JSON.stringify(ctx.cfg.movieLens))}`;
}
async function session(ctx:Ctx):Promise<string> {
  const auth=ctx.cfg.movieLens;
  if (!auth?.username || !auth.password) throw new Error('Connect MovieLens first');
  const key=await sessionKey(ctx),saved=await stateGet<string>(ctx,key);
  if (saved) return unseal(saved,ctx.env,key);
  const r=await safeFetch(`${API}/sessions`,{method:'POST',headers:{'content-type':'application/json;charset=utf-8',accept:'application/json',referer:'https://movielens.org/login'},body:JSON.stringify({userName:auth.username,password:auth.password}),signal:AbortSignal.timeout(15000)});
  const cookie=r.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  await r.body?.cancel();
  if (!r.ok || !cookie) throw new Error('MovieLens rejected the connection');
  await statePut(ctx,key,await seal(cookie,ctx.env,key),86400);
  return cookie;
}
export async function movieLensRead<T>(ctx:Ctx,path:string,init:RequestInit={}):Promise<T> {
  for(let attempt=0;attempt<2;attempt++) {
    const headers=new Headers(init.headers);headers.set('accept','application/json');headers.set('cookie',await session(ctx));
    const r=await safeFetch(`${API}/${path}`,{...init,headers,signal:AbortSignal.timeout(30000)});
    if(r.status===401 && attempt===0) {await r.body?.cancel();await stateDelete(ctx,await sessionKey(ctx));continue;}
    if(!r.ok) {await r.body?.cancel();throw new Error('MovieLens is unavailable');}
    const json=await limitedJson(r) as {data:T;status?:string};
    if(json.status&&json.status!=='success')throw new Error('MovieLens rejected the request');
    return json.data;
  }
  throw new Error('Reconnect MovieLens');
}
export async function movieLensCatalogs(ctx:Ctx):Promise<CatalogDefinition[]> {
  if(!ctx.cfg.movieLens?.username || !ctx.cfg.movieLens.password) return [];
  const out:CatalogDefinition[]=['picks','watchlist','explore'].map(kind=>({id:`movielens.${kind}`,type:'movie',name:kind==='picks'?'Top picks':kind==='watchlist'?'Watchlist':'Explore',group:'MovieLens',extra:[{name:'skip'},{name:'genre'}]}));
  const lists=await memo(`movielens:lists:${await sessionKey(ctx)}`,3600,()=>movieLensRead<Array<{id?:number;listId?:number;name?:string;title?:string;userId?:number}>>(ctx,'users/me/lists')).catch(()=>[]);
  for(const l of lists ?? []) if((l.id||l.listId) && l.userId) out.push({id:`movielens.list.${l.userId}.${l.id||l.listId}`,type:'movie',name:l.name||l.title||'MovieLens list',group:'MovieLens',extra:[{name:'skip'}]});
  return out;
}
export async function movieLensItems(ctx:Ctx,type:ContentType,id:string,extra:CatalogExtra):Promise<MetaPreview[]> {
  if(type!=='movie' || !ctx.cfg.movieLens?.username) return [];
  const skip=Math.max(0,extra.skip??0),page=Math.floor(skip/20)+1;
  const custom=ctx.cfg.customCatalogs?.find(c=>c.provider==='movielens' && id===`movielens.custom.${c.id}`);
  const supplied=custom?.params ?? {};
  const allowed=['sortBy','sortDirection','minYear','maxYear','minPop','maxFutureDays','maxDaysAgo','tag','genre'];
  const p:Record<string,string>={hasRated:'no',sortBy:'prediction',page:String(page),pageSize:'20'};
  for(const k of allowed) if(supplied[k]!==undefined) p[k]=String(supplied[k]);
  if(id==='movielens.explore' || custom) p.maxFutureDays??='0';
  if(p.maxYear) delete p.maxFutureDays;
  if(supplied.includeRated===true) delete p.hasRated;
  if(p.sortBy==='userRating'||p.sortBy==='userRatedDate') p.hasRated='yes';
  if(p.sortBy==='avgRating') p.minPop??='100';
  if(p.sortBy==='releaseDate') p.minPop??='20';
  if(extra.genre) p.genre=extra.genre.toLowerCase();
  if(id==='movielens.watchlist') {delete p.hasRated;p.hasWishlisted='yes';p.sortBy='userListedDate';}
  const list=/^movielens\.list\.(\d+)\.(\d+)$/.exec(id);
  const rows=await memo(`movielens:items:${await sessionKey(ctx)}:${id}:${JSON.stringify(p)}`,3600,async()=> {
    if(list) {
      const collected:MovieRow[]=[];
      for(let n=1;n<=50;n++) {
        const data=await movieLensRead<{searchData?:{searchResults?:MovieRow[]}}>(ctx,`users/${list[1]}/lists/${list[2]}?page=${n}`);
        const batch=data.searchData?.searchResults ?? [];
        if(!batch.length) break;
        collected.push(...batch);
        if(collected.length>=skip+20) break;
      }
      return collected.slice(skip,skip+20);
    }
    const data=await movieLensRead<{searchResults?:MovieRow[]}>(ctx,`movies/explore?${new URLSearchParams(p)}`);
    return data.searchResults??[];
  });
  return (await mapLimit(rows,4,async r=> {
    const m=r.movie,id=m?.tmdbMovieId?`tmdb:${m.tmdbMovieId}`:m?.imdbMovieId?`tt${String(m.imdbMovieId).replace(/^tt/,'')}`:'';
    return id?sourcePreview(ctx,'movie',id,m?.title||id):null;
  })).filter((m):m is MetaPreview=>m!==null);
}
