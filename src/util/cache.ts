import type {Env} from '../env';
import {seal,unseal} from '../security/secrets';
import {sha256} from './bytes';
import {limitedJson,limitedText} from '../security/limits';
import {safeFetch,addonHttpAllowed} from '../security/outbound';
import { tryGetContext } from 'hono/context-storage';

const NS = 'https://rill.cache.invalid/v2/';
const DATABASE_MIN_TTL = 900;

async function keyUrl(key: string, origin?: string): Promise<string> {
  const requestUrl = tryGetContext()?.req.url;
  origin ??= requestUrl ? new URL(requestUrl).origin : undefined;
  return (origin ? `${origin}/.rill-cache-v2/` : NS) + await sha256(key);
}

const hot = new Map<string, {json:string; expires:number}>();
let hotSize = 0;
function forgetHot(url:string):void {
  const entry=hot.get(url);
  if(entry){hotSize-=entry.json.length;hot.delete(url);}
}
function rememberHot(key:string,url:string,json:string,expires:number):void {
  // Only reusable metadata and revision-keyed shelves belong in this cache.
  // Authentication, tracker state and delivery acknowledgements stay fresh.
  if(!/^(jf-meta:|jf-shelf:|catalog-defs:|addon-catalog-defs:|tmdb:|anime:)/.test(key)||json.length>512_000||url.length>16_384)return;
  forgetHot(url);
  while(hot.size>=128||hotSize+json.length>4_000_000)forgetHot(hot.keys().next().value!);
  hot.set(url,{json,expires});hotSize+=json.length;
}

function cacheDatabase(): D1Database | undefined {
  return tryGetContext<{Bindings: {DB?: D1Database}}>()?.env.DB;
}

export async function cacheGet<T>(key: string, origin?: string): Promise<T | null> {
  const url = await keyUrl(key, origin);
  const cached=hot.get(url);
  if(cached&&cached.expires>Date.now())return JSON.parse(cached.json) as T;
  forgetHot(url);
  try {
    const hit = await caches.default.match(url);
    const env=tryGetContext<{Bindings:Env}>()?.env;
    if(hit&&env?.RILL_DATA_KEY)return JSON.parse(await unseal(await limitedText(hit),env,`cache:${url}`)) as T;
  } catch {}
  try {
    const row = await cacheDatabase()?.prepare('SELECT value,expires FROM state WHERE key=? AND expires>?')
      .bind(`cache:${url}`,Date.now()).first<{value:string;expires:number}>();
    if(!row)return null;
    const env=tryGetContext<{Bindings:Env}>()?.env;if(!env?.RILL_DATA_KEY)return null;
    const json=await unseal(row.value,env,`cache:${url}`);
    const value=JSON.parse(json) as T;
    rememberHot(key,url,json,row.expires);
    return value;
  } catch { return null; }
}

export async function cachePut(key: string, value: unknown, ttlSeconds: number, origin?: string): Promise<void> {
  const url = await keyUrl(key, origin);
  let json: string;
  try { json = JSON.stringify(value); } catch { return; }
  if (json === undefined) return;
  const ttl = Math.max(1,Math.floor(ttlSeconds));
  const expires=Date.now()+ttl*1000;
  rememberHot(key,url,json,expires);
  const env=tryGetContext<{Bindings:Env}>()?.env;
  if(!env?.RILL_DATA_KEY)return;
  const encrypted=await seal(json,env,`cache:${url}`);
  try {
    await caches.default.put(url, new Response(encrypted, {
      headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttl}` },
    }));
  } catch {}
  // workers.dev may not retain edge entries. Keep small results in the existing
  // database too; large history imports already have their own chunked storage.
  const db = cacheDatabase();
  if (db && ttl >= DATABASE_MIN_TTL && json.length <= 64_000 && new TextEncoder().encode(json).byteLength <= 64_000) {
    try {
      await db.prepare('INSERT INTO state(key,value,expires) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,expires=excluded.expires')
        .bind(`cache:${url}`,encrypted,expires).run();
    } catch {}
  }
}

export async function cacheDelete(key: string, origin?: string, db = cacheDatabase()): Promise<void> {
  const url = await keyUrl(key, origin);
  forgetHot(url);
  try { await caches.default.delete(url); } catch {}
  if (db) await db.prepare('DELETE FROM state WHERE key=?').bind(`cache:${url}`).run();
}

export async function memo<T>(key: string, ttlSeconds: number, produce: () => Promise<T>): Promise<T> {
  const hit = await cacheGet<T>(key);
  if (hit !== null) return hit;
  const value = await produce();
  if (value !== undefined && value !== null) await cachePut(key, value, ttlSeconds);
  return value;
}

export interface FetchJsonOptions extends RequestInit {
  ttl?: number;
  timeoutMs?: number;
  cacheScope?: string;
  addon?: boolean;
}

export async function fetchJson<T = any>(url: string, opts: FetchJsonOptions = {}): Promise<T | null> {
  const { ttl = 0, timeoutMs = 12000, cacheScope = '', addon=false, ...init } = opts;
  const method = (init.method || 'GET').toUpperCase();
  const key = `json:${cacheScope}:${url}`;
  if (method === 'GET' && ttl > 0) {
    const hit = await cacheGet<T>(key);
    if (hit !== null) return hit;
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await safeFetch(url, { ...init, signal: ctrl.signal },{allowHttp:addon&&addonHttpAllowed()});
    if (!res.ok) {
      await res.body?.cancel();
      return null;
    }
    const data = (await limitedJson(res)) as T;
    if (method === 'GET' && ttl > 0 && data !== null && data !== undefined) await cachePut(key, data, ttl);
    return data;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
