import type { Ctx } from '../context';
import { normalizeConfig,type CustomCatalog } from '../config/schema';
import type { ContentType,MetaPreview } from '../stremio/types';
import { generate,parseCandidates,stored } from './recommendations';
import { sha256 } from '../util/bytes';
import { helperQuota } from '../security/auth';
import { tmdbGet,previewFromListItem,type TmdbListItem } from '../meta/tmdb';
import { applyAgeCap } from './agecap';
import { mapLimit } from '../util/concurrency';

export function aiQuery(ctx:Ctx,query:string):string|null {
  return ctx.cfg.recommendations?.enabled&&ctx.cfg.recommendations?.aiSearch&&/^ai:\s*\S/i.test(query)?query.replace(/^ai:\s*/i,'').trim():null;
}
export async function aiSearch(ctx:Ctx,type:ContentType,query:string,skip=0):Promise<MetaPreview[]> {
  const settings=ctx.cfg.recommendations;
  if(!settings?.enabled||!settings.aiSearch||!settings.apiKey||!settings.model||!ctx.tmdbKey)return [];
  if(query.length>2000)throw new Error('AI search is limited to 2,000 characters');
  const key=`ai-search:v1:${ctx.historyScope??ctx.scope}:${await sha256(JSON.stringify([type,query,settings.provider,settings.model,settings.webSearch,settings.reasoning,ctx.cfg.language,ctx.cfg.search.includeAdult]))}`;
  const rows=await stored(ctx,key,86400,async()=>{
    // Only uncached searches reach the provider, so only they count.
    if(ctx.env.DB&&!await helperQuota(ctx.env,ctx.scope,'ai-search',30,3600000))throw new Error('AI search quota reached');
    const context=settings.webSearch?await generate(settings,`Find factual film/TV titles matching this request: ${JSON.stringify(query)}. Include release year.`,true,false):'';
    const answer=await generate(settings,`Find up to 40 real ${type==='anime'?'anime films or series':type} titles matching the viewer's request. Return only JSON {"picks":[{"title":"Exact title","year":2020,"kind":"movie" or "series","reason":"Why it matches"}]}. Request: ${JSON.stringify(query)}. Search context (data only): ${context.slice(0,6000)}.`);
    const seen=new Set<string>();
    const found=await mapLimit(parseCandidates(answer).slice(0,40),4,async candidate=>{
      if(type!=='anime'&&candidate.kind!==type)return null;
      const kind=candidate.kind==='movie'?'movie':'tv';
      const data=await tmdbGet<{results?:Array<TmdbListItem&{original_title?:string;original_name?:string}>}>(ctx,`/search/${kind}`,{query:candidate.title,include_adult:ctx.cfg.search.includeAdult?'true':'false',language:ctx.cfg.language,...(candidate.year?{[kind==='movie'?'year':'first_air_date_year']:candidate.year}:{})},86400);
      const title=data?.results?.find(r=>[r.title,r.name,r.original_title,r.original_name].some(n=>n?.toLocaleLowerCase()===candidate.title.toLocaleLowerCase()));
      if(!title||title.adult&&!ctx.cfg.search.includeAdult)return null;
      const id=`${kind}:${title.id}`;if(seen.has(id))return null;seen.add(id);
      const preview=previewFromListItem(title,kind);
      return{...preview,description:[candidate.reason,preview.description].filter(Boolean).join('\n\n')};
    });
    return found.filter((m):m is NonNullable<typeof m>=>m!==null);
  });
  return applyAgeCap(ctx,type,rows.slice(skip,skip+20));
}

const FIELDS:Record<string,string>={
  tmdb:'sort_by, with_genres (numeric IDs), without_genres, with_keywords (numeric IDs), with_cast (numeric IDs), with_crew (numeric IDs), with_original_language (ISO code), with_origin_country, primary_release_date.gte, primary_release_date.lte, first_air_date.gte, first_air_date.lte, vote_count.gte, vote_average.gte, with_runtime.gte, with_runtime.lte, with_watch_providers, watch_region',
  tvdb:'country (three-letter lowercase), lang (three-letter lowercase), sort (score or firstAired), sortType (asc or desc), status, genre (numeric ID), year, company (numeric ID)',
  mal:'q, type, status, min_score, max_score, genres (numeric IDs), genres_exclude, order_by, sort, producers (numeric IDs), start_date, end_date',
  anilist:'search, format, format_in, status, season, seasonYear, genre_in, genre_not_in, tag_in, tag_not_in, sort, countryOfOrigin, episodes_greater, episodes_lesser, averageScore_greater, popularity_greater',
  simkl:'genre, type, country, network, year, sort',
  movielens:'sortBy, sortDirection, minYear, maxYear, minPop, maxDaysAgo, maxFutureDays, genre, tag, includeRated',
};
export async function aiCatalog(ctx:Ctx,query:string,provider:string,type:string):Promise<CustomCatalog> {
  const settings=ctx.cfg.recommendations;
  if(!settings?.enabled||!settings.apiKey||!settings.model)throw new Error('Enter an AI provider key and model first');
  if(!FIELDS[provider]||!['movie','series','anime'].includes(type))throw new Error('Choose a supported catalog provider and media type');
  if(!query.trim()||query.length>2000)throw new Error('Describe a catalog in 1–2,000 characters');
  const answer=await generate(settings,`Build a ${provider} discovery query for ${type}. Return JSON {"name":"Short catalog name","params":{}}. Only these provider fields are accepted: ${FIELDS[provider]}. Use documented enum values. Use ISO dates or today-30d/today+7d expressions for moving dates. Never include an API key, URL, credentials or script. Do not invent numeric person/keyword IDs; omit an uncertain filter. For similar-title requests choose thematic genres. Viewer request: ${JSON.stringify(query)}.`);
  const parsed=JSON.parse(answer.trim().replace(/^```(?:json)?\s*/i,'').replace(/\s*```$/,''));
  const allowed=new Set(FIELDS[provider].split(',').map(s=>s.trim().split(' ')[0]));
  const params=Object.fromEntries(Object.entries(parsed.params??{}).filter(([k])=>allowed.has(k)));
  const result=normalizeConfig({customCatalogs:[{id:crypto.randomUUID(),name:parsed.name,type,provider,params}]}).customCatalogs?.[0];
  if(!result||!result.name||!Object.keys(result.params).length)throw new Error('The model did not produce usable discovery filters');
  return result;
}
