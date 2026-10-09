import {seal} from '../security/secrets';
import {generation,readOwner,verifyPassword} from '../security/auth';
import type { Ctx } from '../context';
import { b64urlDecode, b64urlEncode, hmac, sha256, timingSafeEqual } from '../util/bytes';
import { stateDelete, stateGet, statePut } from '../storage/state';

export interface ClientInfo {
  client: string;
  device: string;
  deviceId: string;
  version: string;
}

export interface TokenClaims {
  u: string;
  g: number;
  jti?: string;
  p?: string;
  d: string;
  iat: number;
  s: string;
}

export function parseMediaBrowser(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  const body = header.replace(/^\s*(MediaBrowser|Emby)\s+/i, '');
  const re = /([A-Za-z]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,]*))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    out[m[1].toLowerCase()] = (m[2] ?? m[3] ?? '').trim();
  }
  return out;
}

function authHeader(req: Request): Record<string, string> {
  return parseMediaBrowser(req.headers.get('authorization') || req.headers.get('x-emby-authorization'));
}

export function clientInfoOf(req: Request): ClientInfo {
  const h = authHeader(req);
  return {
    client: h.client || 'Unknown',
    device: h.device || 'Unknown',
    deviceId: h.deviceid || 'unknown',
    version: h.version || '0.0.0',
  };
}

export function tokenOf(req: Request): string {
  const h = authHeader(req);
  if (h.token) return h.token;
  const plain = req.headers.get('x-emby-token') || req.headers.get('x-mediabrowser-token');
  if (plain) return plain.trim();
  const url = new URL(req.url);
  return url.searchParams.get('api_key') || url.searchParams.get('ApiKey') || url.searchParams.get('apikey') || '';
}

const SIGNING_KEY = "install:signing-key";
const FOREVER = 100 * 365 * 86400;
const installKeys=new WeakMap<D1Database,string>();

export async function signingSecret(ctx: Ctx): Promise<string> {
  const fromEnv = ctx.env?.RILL_SECRET?.trim();
  if (fromEnv) return fromEnv;
  if (ctx.env.DB) {
    const cached=installKeys.get(ctx.env.DB);if(cached)return cached;
    const fresh = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    await ctx.env.DB.prepare("INSERT OR IGNORE INTO state(key,value,expires) VALUES(?,?,?)").bind(SIGNING_KEY, await seal(JSON.stringify(fresh),ctx.env,`state:${SIGNING_KEY}`), Date.now() + FOREVER * 1000).run();
    const stored=(await stateGet<string>(ctx,SIGNING_KEY))??fresh;installKeys.set(ctx.env.DB,stored);return stored;
  }
  return sha256(`rill:${ctx.cfg.jellyfin.username}:${ctx.cfg.jellyfin.password}`);
}

export async function mintToken(ctx: Ctx, userId: string, deviceId: string): Promise<string> {
  const claims: TokenClaims = { g:await generation(ctx.env), jti: crypto.randomUUID(), p: ctx.profile?.id, u: userId, d: deviceId, iat: Math.floor(Date.now() / 1000), s: ctx.scope };
  if (ctx.env.DB) await statePut(ctx, `token:${ctx.scope}:${claims.jti}`, true, 30 * 86400);
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify(claims)));
  const sig = await hmac(await signingSecret(ctx), payload);
  return `${payload}.${sig}`;
}

export async function verifyToken(ctx: Ctx, token: string): Promise<TokenClaims | null> {
  if(token.length>4096)return null;
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^[0-9a-f]{64}$/.test(sig)) return null;
  try {
    const expected = await hmac(await signingSecret(ctx), payload);
    if (!timingSafeEqual(expected, sig)) return null;
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(payload))) as TokenClaims;
    if (!claims || claims.g !== await generation(ctx.env) || typeof claims.u !== 'string' || claims.s !== ctx.scope) return null;
    if (!Number.isFinite(claims.iat) || claims.iat > Date.now()/1000+60 || claims.iat < Date.now()/1000-30*86400) return null;
    if (ctx.env.DB && (!claims.jti || !await stateGet(ctx, `token:${ctx.scope}:${claims.jti}`))) return null;
    return claims;
  } catch {
    return null;
  }
}

export async function credentialsMatch(ctx:Ctx,username:unknown,password:unknown):Promise<boolean> {
 const owner=await readOwner(ctx.env);if(!owner)return false;
 const got=String(username??'').trim().toLowerCase();
 return got===ctx.cfg.jellyfin.username.trim().toLowerCase()&&await verifyPassword(owner,password);
}

export interface Identity {
  serverId: string;
  userId: string;
}

export async function identityOf(ctx: Ctx): Promise<Identity> {
  const [server, user] = await Promise.all([sha256(`rill:jellyfin:server:${ctx.scope}`), sha256(`rill:jellyfin:user:${ctx.scope}`)]);
  return { serverId: server.slice(0,32), userId:ctx.profile ? (await sha256(`rill:jellyfin:profile:${ctx.scope}:${ctx.profile.id}`)).slice(0,32) : user.slice(0,32) };
}

const QC_TTL = 10 * 60;

export interface QuickConnectRecord {
  secret: string;
  generation: number;
  code: string;
  client: ClientInfo;
  dateAdded: string;
  authenticated: boolean;
  profileId?: string;
}

const codeKey = (ctx: Ctx, code: string) => `jf:qc:code:${ctx.scope}:${code}`;
const secretKey = (ctx: Ctx, secret: string) => `jf:qc:secret:${ctx.scope}:${secret}`;

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let s = '';
  for (const b of buf) s += b.toString(16).padStart(2, '0');
  return s;
}

async function storeQuickConnect(ctx: Ctx, rec: QuickConnectRecord): Promise<void> {
  await Promise.all([statePut(ctx, secretKey(ctx, rec.secret), rec, QC_TTL), statePut(ctx, codeKey(ctx, rec.code), { secret: rec.secret }, QC_TTL)]);
}

export async function startQuickConnect(ctx: Ctx, client: ClientInfo): Promise<QuickConnectRecord> {
  const digits = new Uint32Array(1);
  crypto.getRandomValues(digits);
  const rec: QuickConnectRecord = {
    generation:await generation(ctx.env),
    secret: randomHex(24),
    code: String(digits[0] % 1_000_000).padStart(6, '0'),
    client,
    dateAdded: new Date().toISOString(),
    authenticated: false,
  };
  if (ctx.env.DB) {
    for (let attempt=0;attempt<8;attempt++) {
      const stored=await ctx.env.DB.prepare('INSERT INTO state(key,value,expires) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,expires=excluded.expires WHERE state.expires<=? RETURNING key')
        .bind(codeKey(ctx,rec.code),JSON.stringify({secret:rec.secret}),Date.now()+QC_TTL*1000,Date.now()).first();
      if (stored) { await statePut(ctx,secretKey(ctx,rec.secret),rec,QC_TTL); return rec; }
      crypto.getRandomValues(digits);rec.code=String(digits[0]%1_000_000).padStart(6,'0');
    }
    throw new Error('Quick Connect codes busy');
  }
  await storeQuickConnect(ctx, rec);
  return rec;
}

export async function readQuickConnect(ctx: Ctx, secret: string): Promise<QuickConnectRecord | null> {
  if (!secret || !/^[0-9a-f]{16,64}$/i.test(secret)) return null;
  return stateGet<QuickConnectRecord>(ctx, secretKey(ctx, secret.toLowerCase()));
}

export async function approveQuickConnect(ctx: Ctx, code: string): Promise<QuickConnectRecord | null> {
  const clean = String(code ?? '').replace(/\D/g, '');
  if (clean.length !== 6) return null;
  const ref = await stateGet<{ secret: string }>(ctx, codeKey(ctx, clean));
  if (!ref?.secret) return null;
  if (ctx.env.DB) {
    const row=await ctx.env.DB.prepare("UPDATE state SET value=json_set(value,'$.authenticated',json('true'),'$.profileId',?) WHERE key=? AND expires>? AND json_extract(value,'$.authenticated')=0 RETURNING value")
      .bind(ctx.profile?.id ?? null,secretKey(ctx,ref.secret),Date.now()).first<{value:string}>();
    return row ? JSON.parse(row.value) as QuickConnectRecord : null;
  }
  const rec = await readQuickConnect(ctx, ref.secret);
  if (!rec) return null;
  rec.authenticated = true;
  rec.profileId = ctx.profile?.id;
  await storeQuickConnect(ctx, rec);
  return rec;
}

export async function claimQuickConnect(ctx: Ctx, secret: string): Promise<QuickConnectRecord | null> {
  if (ctx.env.DB) {
    const row = await ctx.env.DB.prepare("DELETE FROM state WHERE key=? AND expires>? AND json_extract(value,'$.authenticated')=1 RETURNING value").bind(secretKey(ctx,secret.toLowerCase()),Date.now()).first<{value:string}>();
    if (!row) return null;
    const rec = JSON.parse(row.value) as QuickConnectRecord;
    if(rec.generation!==await generation(ctx.env))return null;
    await stateDelete(ctx,codeKey(ctx,rec.code));
    return rec;
  }
  const rec = await readQuickConnect(ctx, secret);
  if (!rec?.authenticated) return null;
  await Promise.all([stateDelete(ctx, secretKey(ctx, rec.secret)), stateDelete(ctx, codeKey(ctx, rec.code))]);
  return rec;
}

export function quickConnectDto(rec: QuickConnectRecord): Record<string, unknown> {
  return {
    Authenticated: rec.authenticated,
    Secret: rec.secret,
    Code: rec.code,
    DeviceId: rec.client.deviceId,
    DeviceName: rec.client.device,
    AppName: rec.client.client,
    AppVersion: rec.client.version,
    DateAdded: rec.dateAdded,
  };
}

export async function revokeToken(ctx: Ctx, token: string): Promise<void> {
  const claims = await verifyToken(ctx,token);
  if (claims?.jti) await stateDelete(ctx,`token:${ctx.scope}:${claims.jti}`);
}
