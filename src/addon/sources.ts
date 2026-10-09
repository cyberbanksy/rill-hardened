import {limitedJson,limitedText} from '../security/limits';
import {safeFetch,addonHttpAllowed} from '../security/outbound';
import type { Ctx } from '../context';
import type { ContentType, MetaPreview } from '../stremio/types';
import type { CatalogDefinition, CatalogExtra } from './catalogs';
import { fetchJson, memo } from '../util/cache';
import { mapLimit, uniq } from '../util/concurrency';
import { artworkUrl, tvdbGet, tvdbMeta, type TvdbRecord } from '../meta/tvdb';
import { tmdbGet, previewFromListItem, type TmdbListItem } from '../meta/tmdb';
import { movieLensCatalogs, movieLensItems } from './movielens';
import { previewFromShow,type TvmazeShow } from '../meta/tvmaze';
import { AIRING_REGIONS } from './tables';
import { socialDefinitions,socialItems } from './social-discovery';

const PAGE = 20;
const chartBase = 'https://raw.githubusercontent.com/0xConstant1/fp-crawler/main/catalogs';
const extra = [{ name: 'skip' }];
interface TvdbList { id: number; name?: string; image?: string; overview?: string; entities?: Array<{ movieId?: number; seriesId?: number; order?: number }> }
interface ListFilm { title?: string; type?: string; genre_ids?: number[]; id_map?: { imdb?: string; tmdb?: string | number; anime?: { mal?: string | number } } }
interface LetterList { data?: { title?: string; items?: ListFilm[] } }
interface Chart { catalog_id: string; heading?: string; entries: Array<{ rank: number; title: string; tmdb?: { id: number; media_type: string; release_date?: string } }> }
interface Charts { charts?: Chart[] }

function tvdbListId(ref: string): string | null {
  const raw = ref.replace(/^https?:\/\/(?:www\.)?thetvdb.com\/lists\//, '').replace(/\/$/, '');
  return /^[\w-]+$/.test(raw) ? raw : null;
}
async function tvdbList(ctx: Ctx, ref: string): Promise<TvdbList | null> {
  const id = tvdbListId(ref);
  if (!id) return null;
  if (/^\d+$/.test(id)) return tvdbGet(ctx, `/lists/${id}/extended`, 3600);
  const found = await tvdbGet<TvdbList>(ctx, `/lists/slug/${encodeURIComponent(id)}`, 3600);
  return found?.id ? tvdbGet(ctx, `/lists/${found.id}/extended`, 3600) : null;
}

export async function sourcePreview(ctx: Ctx, type: 'movie' | 'series', id: string, title: string): Promise<MetaPreview> {
  const n = Number(id.split(':')[1]);
  if (id.startsWith('tmdb:') && ctx.tmdbKey) {
    const row = await tmdbGet<TmdbListItem&{imdb_id?:string;external_ids?:{imdb_id?:string;tvdb_id?:number};genres?:Array<{name:string}>}>(ctx, `/${type === 'movie' ? 'movie' : 'tv'}/${n}`, { language: ctx.cfg.language,append_to_response:'external_ids' }, 3600);
    if (row?.id) return Object.assign(previewFromListItem(row, type === 'movie' ? 'movie' : 'tv'),{genres:row.genres?.map(g=>g.name),ids:{tmdb:row.id,imdb:row.imdb_id??row.external_ids?.imdb_id,tvdb:row.external_ids?.tvdb_id}});
  }
  if (id.startsWith('tvdb:') && ctx.cfg.keys.tvdb) {
    const meta = await tvdbMeta(ctx, type, n, id, { withEpisodes: false });
    if (meta) return meta;
  }
  return { id, type, name: title, ...(/^tt\d+$/.test(id) ? { poster: `https://images.metahub.space/poster/medium/${id}/img` } : {}) };
}

export async function letterboxdReference(raw: string): Promise<{ id: string; watchlist: boolean }> {
  if (/^(watchlist:)?[\w-]+$/.test(raw)) return { id:raw.replace(/^watchlist:/,''), watchlist:raw.startsWith('watchlist:') };
  const url = new URL(raw);
  if (url.protocol !== 'https:' || !['letterboxd.com','www.letterboxd.com'].includes(url.hostname) || url.username || url.password) throw new Error('Use a Letterboxd list or watchlist URL');
  const parts = url.pathname.split('/').filter(Boolean);
  const watchlist = parts[1] === 'watchlist';
  if (!watchlist && (parts[1] !== 'list' || !parts[2])) throw new Error('Use a Letterboxd list or watchlist URL');
  const page = watchlist ? `https://letterboxd.com/${encodeURIComponent(parts[0])}/` : url.href;
  return memo(`letterboxd:identifier:${page}`,86400,async () => {
    const r = await safeFetch(page,{headers:{accept:'text/html'},signal:AbortSignal.timeout(15000)});
    const id = r.headers.get('x-letterboxd-identifier');
    await r.body?.cancel();
    if (!r.ok || !id || !/^[\w-]+$/.test(id)) throw new Error('Letterboxd did not provide a list identifier; enter its identifier directly');
    return {id,watchlist};
  });
}
async function letterList(raw: string): Promise<LetterList | null> {
  const ref = await letterboxdReference(raw);
  const path = ref.watchlist ? `users/${ref.id}/lists/watchlist` : `lists/${ref.id}`;
  return fetchJson(`https://stremthru.13377001.xyz/v0/meta/letterboxd/${path}`,{ttl:7200});
}

export async function sourceDefinitions(ctx: Ctx): Promise<CatalogDefinition[]> {
  const out: CatalogDefinition[] = [];
  out.push(...socialDefinitions(ctx));
  out.push({id:'tvmaze.schedule',type:'series',name:'Airing today',group:'TVmaze',extra:[{name:'genre',options:AIRING_REGIONS},...extra]});
  if (ctx.cfg.keys.tvdb) {
    out.push({id:'tvdb.collections',type:'movie',name:'Movie collections',group:'TVDB',extra});
    const genres = await tvdbGet<Array<{id:number;name:string}>>(ctx,'/genres',86400) ?? [];
    for (const type of ['movie','series'] as const) for (const kind of ['trending','popular','genre']) out.push({id:`tvdb.${kind}`,type,name:kind === 'genre' ? 'By Genre' : kind === 'trending' ? 'Trending' : 'Popular',group:'TVDB',extra:[{name:'genre',options:genres.map(g=>g.name),isRequired:kind==='genre'},...extra],genres:genres.map(g=>g.name)});
    for (const ref of ctx.cfg.lists.tvdb ?? []) {
      const list = await tvdbList(ctx,ref);
      if (!list) continue;
      for (const type of ['movie','series'] as const) if (list.entities?.some(e=>type==='movie' ? e.movieId : e.seriesId)) out.push({id:`tvdb.list.${list.id}`,type,name:list.name || `TVDB ${list.id}`,group:'TVDB lists',extra});
    }
  }
  for (const [i,ref] of (ctx.cfg.thirdParty?.letterboxd ? ctx.cfg.lists.letterboxd ?? [] : []).entries()) {
    const data = await letterList(ref).catch(()=>null);
    for (const type of ['movie','series'] as const) {
      if (type==='series' && !data?.data?.items?.some(r=>r.type==='show')) continue;
      out.push({id:`letterboxd.${i}`,type,name:data?.data?.title || `Letterboxd ${i+1}`,group:'Letterboxd',extra});
    }
  }
  for (const region of ctx.cfg.lists.flixpatrol ?? []) {
    if (!/^[a-z-]+$/.test(region)) continue;
    const data = await fetchJson<Charts>(`${chartBase}/${region==='world'?'global':region}.json`,{ttl:3600});
    for (const chart of data?.charts ?? []) for (const type of ['movie','series'] as const) if (chart.entries.some(e=>(e.tmdb?.media_type==='movie'?'movie':'series')===type)) out.push({id:`flixpatrol.${region}.${chart.catalog_id}`,type,name:`${chart.heading || chart.catalog_id} · ${region}`,group:'FlixPatrol',extra});
  }
  out.push(...await movieLensCatalogs(ctx));
  for(const ref of ctx.cfg.lists.tmdbCollections??[]) {
    const id=/^(?:https?:\/\/(?:www\.)?themoviedb.org\/collection\/)?(\d+)/.exec(ref)?.[1];
    if(!id)continue;
    const detail=await tmdbGet<{name?:string}>(ctx,`/collection/${id}`,{language:ctx.cfg.language},86400);
    out.push({id:`tmdb.collection.${id}`,type:'movie',name:detail?.name??`TMDB Collection ${id}`,group:'TMDB collections',extra});
  }
  for (const c of ctx.cfg.customCatalogs ?? []) out.push({id:`${c.provider}.custom.${c.id}`,type:c.type,name:c.name,group:c.provider==='merged'?'Merged catalogs':'Custom discovery',extra});
  return out;
}

export async function sourceItems(ctx: Ctx, type: ContentType, id: string, query: CatalogExtra): Promise<MetaPreview[] | null> {
  const skip = Math.max(0,query.skip ?? 0);
  if(['movie','series','anime'].includes(type)){const social=await socialItems(ctx,type as 'movie'|'series'|'anime',id,query);if(social!==null)return social;}
  if(id==='tvmaze.schedule') {
    if(type!=='series')return [];
    const country=query.genre?.match(/\b[A-Z]{2}\b/)?.[0]??ctx.cfg.language.split('-')[1]??'US';
    const params=new URLSearchParams({date:new Date().toISOString().slice(0,10),country});
    const rows=await fetchJson<Array<{airstamp?:string;show?:TvmazeShow}>>(`https://api.tvmaze.com/schedule?${params}`,{ttl:1800});
    if(!rows)throw new Error('TVmaze schedule is unavailable');
    return uniq(rows.filter(r=>r.show?.id&&!['news','talk show'].includes(r.show.type?.toLowerCase()??'')).sort((a,b)=>String(a.airstamp??'').localeCompare(String(b.airstamp??''))),r=>String(r.show!.id)).slice(skip,skip+PAGE).map(r=>previewFromShow(r.show!));
  }
  if (id.startsWith('movielens.')) return movieLensItems(ctx,type,id,query);
  if (id.startsWith('letterboxd.')) {
    if(!ctx.cfg.thirdParty?.letterboxd)return [];
    const ref = ctx.cfg.lists.letterboxd?.[Number(id.slice(11))];
    if (!ref) return [];
    const data = await letterList(ref);
    if (!data) throw new Error('Letterboxd is unavailable');
    const rows = (data.data?.items ?? []).filter(r=>(r.type==='show'?'series':'movie')===type).slice(skip,skip+PAGE);
    return (await mapLimit(rows,4,async r=> {
      const ids=r.id_map;
      const key=ids?.imdb || (ids?.tmdb ? `tmdb:${ids.tmdb}` : ids?.anime?.mal ? `mal:${ids.anime.mal}` : '');
      return key ? sourcePreview(ctx,type as 'movie'|'series',key,r.title || key) : null;
    })).filter((m):m is MetaPreview=>m!==null);
  }
  if (id.startsWith('flixpatrol.')) {
    const [,region,...rest]=id.split('.');
    if (!ctx.cfg.lists.flixpatrol?.includes(region)) return [];
    const data=await fetchJson<Charts>(`${chartBase}/${region==='world'?'global':region}.json`,{ttl:3600});
    const chart=data?.charts?.find(c=>c.catalog_id===rest.join('.'));
    const rows=(chart?.entries ?? []).filter(e=>e.tmdb && (e.tmdb.media_type==='movie'?'movie':'series')===type).slice(skip,skip+PAGE);
    return mapLimit(rows,4,r=>sourcePreview(ctx,type as 'movie'|'series',`tmdb:${r.tmdb!.id}`,r.title));
  }
  if (id.startsWith('tvdb.list.')) {
    const list=await tvdbList(ctx,id.slice(10));
    const rows=(list?.entities ?? []).filter(e=>type==='movie'?e.movieId:e.seriesId).sort((a,b)=>(a.order??0)-(b.order??0)).slice(skip,skip+PAGE);
    return mapLimit(rows,4,e=>sourcePreview(ctx,type as 'movie'|'series',`tvdb:${type==='movie'?e.movieId:e.seriesId}`,'Untitled'));
  }
  if (['tvdb.trending','tvdb.popular','tvdb.genre'].includes(id)) {
    const p:Record<string,string>={country:'usa',lang:'eng',sort:'score',...(type==='movie'?{status:'5'}:{sortType:'desc'})};
    if (query.genre) {
      const genres=await tvdbGet<Array<{id:number;name:string}>>(ctx,'/genres',86400);
      const g=genres?.find(g=>g.name.toLowerCase()===query.genre!.toLowerCase());
      if (g) p.genre=String(g.id); else if(id==='tvdb.genre') return [];
    } else if(id==='tvdb.genre') return [];
    const get=(params:Record<string,string>)=>tvdbGet<Array<TvdbRecord & {score?:number}>>(ctx,`/${type==='movie'?'movies':'series'}/filter?${new URLSearchParams(params)}`,3600);
    const now=new Date();
    const rows=id==='tvdb.trending' ? (await Promise.all([get({...p,year:String(now.getUTCFullYear())}),get({...p,year:String(now.getUTCFullYear()-1)})])).flatMap(r=>r??[]) : await get(p) ?? [];
    return uniq(rows,r=>String(r.id)).filter(r=>id!=='tvdb.trending'||type==='movie'||r.firstAired && Date.parse(r.firstAired)<=Date.now()+7*86400_000).sort((a,b)=>(b.score??0)-(a.score??0)).slice(skip,skip+PAGE).map(r=>({id:`tvdb:${r.id}`,type,name:r.name,description:r.overview,poster:artworkUrl(r.image),released:r.firstAired,year:Number(r.year)||undefined}));
  }
  return null;
}
