import {imageResponse} from '../jellyfin/images';
import {artworkTag,imageTaggedJson,imageUrlByTag} from '../jellyfin/image-tags';
import type {JfRequest} from '../jellyfin/request';
import { Hono } from 'hono';
import type { Ctx } from '../context';
import type { ContentType, Meta, Stream, Subtitle } from '../stremio/types';
import { externalMeta, externalStreams, externalSubtitles } from '../stremio/client';
import { metaApi } from '../meta/index';
import { buildManifest } from './manifest';
import { catalogItems, type CatalogExtra } from './catalogs';
import { collectionMembers } from './collections';

export { listCatalogDefinitions, catalogItems } from './catalogs';
export type { CatalogDefinition, CatalogExtra } from './catalogs';
export { buildManifest } from './manifest';
export { unifiedSearch } from './search';

type AddonEnv = { Variables: { ctx: Ctx } };

export const addonRouter = new Hono<AddonEnv>();

const MAX_AGE = { manifest: 3600, catalog: 900, meta: 3600, stream: 60, subtitles: 600, empty: 30 } as const;

const CONTENT_TYPES = new Set<ContentType>(['movie', 'series', 'anime', 'channel', 'tv']);

function stremioType(raw: string): ContentType {
  return CONTENT_TYPES.has(raw as ContentType) ? (raw as ContentType) : 'movie';
}

function bare(segment: string): string {
  const s = safeDecode(segment);
  return s.endsWith('.json') ? s.slice(0, -5) : s;
}

function parseExtra(segment: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!segment) return out;
  for (const pair of bare(segment).split('&')) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const k = safeDecode(pair.slice(0, eq)).trim();
    const v = safeDecode(pair.slice(eq + 1)).trim();
    if (k && v) out[k] = v;
  }
  return out;
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; }
}

function toCatalogExtra(raw: Record<string, string>): CatalogExtra {
  const skip = Number.parseInt(raw.skip ?? '', 10);
  const extra: CatalogExtra = {};
  if (raw.search) extra.search = raw.search;
  if (raw.genre) extra.genre = raw.genre;
  if (Number.isFinite(skip) && skip > 0) extra.skip = skip;
  return extra;
}

function json(body: unknown, maxAge: number): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': `public, max-age=${maxAge}, stale-while-revalidate=${maxAge}`,
      'access-control-allow-origin': '*',
      'access-control-allow-headers': '*',
      'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    },
  });
}

addonRouter.use('*', async (c, next) => {
  if (c.req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': 'GET, HEAD, OPTIONS', 'access-control-max-age': '86400' },
    });
  }
  await next();
  c.header('access-control-allow-origin', '*');
});

async function publicJson(ctx:Ctx,body:unknown,maxAge:number):Promise<Response> {
 const mappings:Record<string,string>={};
 const artwork=new Set(['poster','background','logo','thumbnail','cover','backdrop','avatar']);
 const transform=(value:unknown,key=''):unknown=>{
  if(typeof value==='string'&&/^https?:\/\//i.test(value)&&artwork.has(key)) {
   const tag=artworkTag(value,ctx.env.RILL_DATA_KEY);mappings[tag]=value;return `${ctx.origin}/${ctx.cfgToken}/media/${tag}`;
  }
  if(Array.isArray(value))return value.map(v=>transform(v,key));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,transform(v,k)]));
  return value;
 };
 const result=transform(body);
 if(Object.keys(mappings).length)await imageTaggedJson(ctx,{ImageTags:mappings},(_k,v)=>v);
 return json(result,maxAge);
}
addonRouter.get('/media/:tag',async c=>{
 const ctx=c.get('ctx'),url=await imageUrlByTag(ctx,c.req.param('tag'));if(!url)return c.body(null,404);
 return imageResponse({ctx,q:()=>undefined} as unknown as JfRequest,c.req.raw,url,'primary');
});

addonRouter.get('/manifest.json', async (c) => {
  const ctx = c.get('ctx');
  const manifest = await buildManifest(ctx);
  return json(manifest, MAX_AGE.manifest);
});

async function catalogResponse(ctx: Ctx, type: string, id: string, rawExtra: Record<string, string>): Promise<Response> {
  const extra = toCatalogExtra(rawExtra);
  let metas: Awaited<ReturnType<typeof catalogItems>> = [];
  try {
    metas = await catalogItems(ctx, stremioType(type), bare(id), extra);
  } catch {
    metas = [];
  }
  const age = extra.search ? MAX_AGE.empty : metas.length ? MAX_AGE.catalog : MAX_AGE.empty;
  return publicJson(ctx,{metas},age);
}

addonRouter.get('/catalog/:type/:id', (c) => catalogResponse(c.get('ctx'), c.req.param('type'), c.req.param('id'), {}));
addonRouter.get('/catalog/:type/:id/:extra', (c) => catalogResponse(c.get('ctx'), c.req.param('type'), c.req.param('id'), parseExtra(c.req.param('extra'))));

addonRouter.get('/meta/:type/:id', async (c) => {
  const ctx = c.get('ctx');
  const type = stremioType(c.req.param('type'));
  const id = bare(c.req.param('id'));
  let meta: Meta | null = null;
  try { meta = await metaApi.resolveMeta(ctx, type, id); } catch { meta = null; }
  if (!meta) {
    try { meta = await externalMeta(ctx, type, id); } catch { meta = null; }
  }
  if(meta?.collection) {
    const members=await collectionMembers(ctx,id,0,1000);
    if(members.total>1000)throw new Error('Collection is too large for one metadata response');
    meta.videos=members.items.map(m=>({id:m.id,title:m.name,thumbnail:m.poster,released:(m as Meta).released}));
  }
  return publicJson(ctx,{ meta: meta ?? null }, meta ? MAX_AGE.meta : MAX_AGE.empty);
});

addonRouter.get('/stream/:type/:id', async (c) => {
  const ctx = c.get('ctx');
  const type = stremioType(c.req.param('type'));
  const id = bare(c.req.param('id'));
  const [streams, subtitles] = await Promise.all([
    externalStreams(ctx, type, id).catch(() => [] as Stream[]),
    ctx.cfg.addons.subtitle.length ? externalSubtitles(ctx, type, id).catch(() => [] as Subtitle[]) : Promise.resolve([] as Subtitle[]),
  ]);
  const out: Stream[] = streams.map((s) => {
    const { addon, ...rest } = s as Stream & { addon?: string };
    const stream: Stream = { ...rest };
    if (addon && !stream.name) stream.name = addon;
    if (subtitles.length && !stream.subtitles?.length) stream.subtitles = subtitles;
    return stream;
  });
  return publicJson(ctx,{ streams: out }, out.length ? MAX_AGE.stream : MAX_AGE.empty);
});

async function subtitlesResponse(ctx: Ctx, type: string, id: string, rawExtra: Record<string, string>): Promise<Response> {
  const size = Number.parseInt(rawExtra.videoSize ?? '', 10);
  const extra = {
    filename: rawExtra.filename || undefined,
    videoHash: rawExtra.videoHash || undefined,
    videoSize: Number.isFinite(size) && size > 0 ? size : undefined,
  };
  let subtitles: Subtitle[] = [];
  try { subtitles = await externalSubtitles(ctx, stremioType(type), bare(id), extra); } catch { subtitles = []; }
  return publicJson(ctx,{ subtitles }, subtitles.length ? MAX_AGE.subtitles : MAX_AGE.empty);
}

addonRouter.get('/subtitles/:type/:id', (c) => subtitlesResponse(c.get('ctx'), c.req.param('type'), c.req.param('id'), {}));
addonRouter.get('/subtitles/:type/:id/:extra', (c) => subtitlesResponse(c.get('ctx'), c.req.param('type'), c.req.param('id'), parseExtra(c.req.param('extra'))));
