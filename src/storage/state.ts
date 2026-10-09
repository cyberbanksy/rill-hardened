import type { Ctx } from '../context';
import { cacheDelete, cacheGet, cachePut } from '../util/cache';
import { loadConfig,storeConfig,seal,unseal } from '../security/secrets';
import { readOwner } from '../security/auth';
import { sha256 } from '../util/bytes';

export async function stateGet<T>(ctx: Ctx, key: string): Promise<T | null> {
  if (!ctx.env.DB) return cacheGet<T>(key);
  const row = await ctx.env.DB.prepare('SELECT value FROM state WHERE key = ? AND expires > ?').bind(key, Date.now()).first<{ value: string }>();
  return row ? JSON.parse(row.value.startsWith('e1.')?await unseal(row.value,ctx.env,`state:${key}`):row.value) as T : null;
}

export async function statePut(ctx: Ctx, key: string, value: unknown, ttl: number): Promise<void> {
  if (!ctx.env.DB) return cachePut(key, value, ttl);
  await ctx.env.DB.prepare('INSERT INTO state(key,value,expires) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,expires=excluded.expires')
    .bind(key, /^(recommendations:|taste:)/.test(key)?await seal(JSON.stringify(value),ctx.env,`state:${key}`):JSON.stringify(value), Date.now() + ttl * 1000).run();
}

export async function stateDelete(ctx: Ctx, key: string): Promise<void> {
  if (!ctx.env.DB) { await cacheDelete(key, ctx.origin, ctx.env.DB); return; }
  await ctx.env.DB.prepare('DELETE FROM state WHERE key=?').bind(key).run();
}

export async function registerAccount(ctx: Ctx, activate = false): Promise<void> {
  if (!ctx.env.DB) return;
  const owner=await readOwner(ctx.env);
  if(!owner || ctx.scope!==(await sha256(owner.installation_key)).slice(0,32)) throw Error('Owner scope required');
  if (activate) {
    const previous = await ctx.env.DB.prepare('SELECT config FROM accounts WHERE scope=?').bind(ctx.scope).first<{config:string}>();
    const old = previous ? await loadConfig(previous.config,ctx.env,ctx.scope) : null;
    for (const service of ['trakt','mal'] as const) {
      const supplied = ctx.cfg.trackers[service], before = old?.trackers[service];
      if (supplied?.accessToken && (!before || supplied.accessToken !== before.accessToken || supplied.clientId !== before.clientId)) {
        await ctx.env.DB.prepare('INSERT INTO credentials(scope,service,value) VALUES(?,?,?) ON CONFLICT(scope,service) DO UPDATE SET value=excluded.value,lease=NULL,lease_until=0')
          .bind(ctx.scope,service,await seal(JSON.stringify(supplied),ctx.env,`credential:${ctx.scope}:${service}`)).run();
      }
    }
  }
  await ctx.env.DB.prepare(`INSERT INTO accounts(scope,config,origin,sync_after) VALUES(?,?,?,?) ON CONFLICT(scope) ${activate ? 'DO UPDATE SET config=excluded.config,origin=excluded.origin,sync_after=excluded.sync_after' : 'DO NOTHING'}`)
    .bind(ctx.scope, await storeConfig(ctx.cfg,ctx.env,ctx.scope), ctx.origin, Date.now() + 120_000).run();
}
