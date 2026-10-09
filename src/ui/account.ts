import { addonCapability } from '../security/capability';
import type { Hono } from 'hono';
import type { Ctx } from '../context';
import type { Env } from '../env';
import { normalizeConfig, type RillConfig } from '../config/schema';
import { registerAccount, stateDelete, stateGet, statePut } from '../storage/state';
import { signingSecret } from '../jellyfin/auth';
import { b64urlDecode, b64urlEncode, hmac, sha256, timingSafeEqual } from '../util/bytes';
import { readOwner, verifyPassword, passwordHash, claimOwner, loginThrottle, resetLogin, type OwnerRow } from '../security/auth';
import { loadConfig, mergePrivate, publicConfig, storeConfig } from '../security/secrets';
import { limitedJson } from '../security/limits';
const COOKIE = 'rill_owner', SESSION_DAYS = 30;
type BuildCtx = (cfg: RillConfig, env: Env, origin: string) => Promise<Ctx>;
function cookieValue(req: Request): string { return req.headers.get('cookie')?.split(';').map(p => p.trim()).find(p => p.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1) ?? ''; }
function sessionCtx(env: Env, req: Request): Ctx { return { cfg: normalizeConfig({}), env, scope: 'owner', cfgToken: '', origin: new URL(req.url).origin, lang: 'en', tmdbKey: undefined }; }
async function sessionKey(ctx: Ctx): Promise<string> { return sha256(`rill:owner-session:${await signingSecret(ctx)}`); }
async function mintSession(env: Env, req: Request, owner: OwnerRow): Promise<string> {
    const ctx = sessionCtx(env, req), claims = { exp: Date.now() + SESSION_DAYS * 86400000, n: crypto.randomUUID(), g: owner.auth_generation };
    await statePut(ctx, `owner-session:${claims.n}`, true, SESSION_DAYS * 86400);
    const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify(claims)));
    return `${payload}.${await hmac(await sessionKey(ctx), payload)}`;
}
export async function ownerSession(env: Env, req: Request): Promise<OwnerRow | null> {
    const owner = await readOwner(env);
    if (!owner)
        return null;
    const value = cookieValue(req);
    if (value.length > 2048)
        return null;
    const [payload, sig] = value.split('.');
    if (!payload || !sig)
        return null;
    const ctx = sessionCtx(env, req);
    if (!timingSafeEqual(await hmac(await sessionKey(ctx), payload), sig))
        return null;
    try {
        const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
        return claims.g === owner.auth_generation && claims.exp > Date.now() && typeof claims.n === 'string' && await stateGet(ctx, `owner-session:${claims.n}`) ? owner : null;
    }
    catch {
        return null;
    }
}
function setCookie(origin: string, value: string, maxAge: number): string { return `${COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${origin.startsWith('https:') ? '; Secure' : ''}`; }
export async function ownerConfig(env: Env, owner: OwnerRow): Promise<RillConfig | null> {
    const scope = (await sha256(owner.installation_key)).slice(0, 32);
    const row = await env.DB!.prepare('SELECT config FROM accounts WHERE scope=?').bind(scope).first<{
        config: string;
    }>();
    return row ? loadConfig(row.config, env, scope) : null;
}
export function mountAccountRoutes(router: Hono<{
    Variables: {
        ctx?: Ctx;
        ownerCfg: RillConfig;
    };
    Bindings: Env;
}>, buildCtx: BuildCtx): void {
    router.post('/api/account/status', async (c) => { const owner = await readOwner(c.env), signed = owner && await ownerSession(c.env, c.req.raw); return c.json({ durable: Boolean(c.env.DB), exists: Boolean(owner), signedIn: Boolean(signed), username: signed ? owner!.username : undefined }); });
    router.post('/api/account/login', async (c) => {
        const retry = await loginThrottle(c.env, c.req.raw);
        if (retry) {
            c.header('Retry-After', String(retry));
            return c.json({ error: 'Try again later.' }, 429);
        }
        const owner = await readOwner(c.env), body = await limitedJson<Record<string, unknown>>(c.req.raw, 262144);
        const valid = owner && await verifyPassword(owner, body.password);
        if (!valid || String(body.username ?? '').trim().toLowerCase() !== owner!.username.toLowerCase())
            return c.json({ error: 'Wrong username or password.' }, 401);
        await resetLogin(c.env);
        c.header('Set-Cookie', setCookie(new URL(c.req.url).origin, await mintSession(c.env, c.req.raw, owner!), SESSION_DAYS * 86400));
        const cfg = await ownerConfig(c.env, owner!);
        return c.json({ config: cfg ? publicConfig(cfg) : null, username: owner!.username });
    });
    router.post('/api/account/load', async (c) => { const owner = await ownerSession(c.env, c.req.raw); if (!owner)
        return c.json({ error: 'Sign in first.' }, 401); const cfg = await ownerConfig(c.env, owner); return c.json({ config: cfg ? publicConfig(cfg) : null, username: owner.username }); });
    router.post('/api/account/save', async (c) => {
        if (!c.env.DB || !c.env.RILL_DATA_KEY)
            return c.json({ error: 'Configure durable storage and RILL_DATA_KEY first.' }, 503);
        const owner = await readOwner(c.env);
        if (owner && !await ownerSession(c.env, c.req.raw))
            return c.json({ error: 'Sign in first.' }, 401);
        const body = await limitedJson<Record<string, unknown>>(c.req.raw, 262144);
        const previous = owner ? await ownerConfig(c.env, owner) : null;
        const cfg = previous ? mergePrivate(body.config, previous) : normalizeConfig(body.config);
        const username = String(cfg.jellyfin.username ?? '').trim(), password = cfg.jellyfin.password;
        if ((!owner || username !== owner.username) && !/^[a-z0-9._-]{1,32}$/i.test(username) || typeof password !== 'string' || password.length > 1024 || (!owner || password) && password.length < 8)
            return c.json({ error: 'Set a valid username and a password of at least 8 characters.' }, 400);
        if (!owner) {
            if (!c.env.RILL_SETUP_TOKEN || !timingSafeEqual(String(body.setupToken ?? ''), c.env.RILL_SETUP_TOKEN))
                return c.json({ error: 'A provisioning token is required.' }, 403);
            cfg.installationKey = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
            // Validate encryption key and config limits before claiming the singleton.
            await storeConfig(cfg, c.env, (await sha256(cfg.installationKey)).slice(0, 32));
            if (!await claimOwner(c.env, cfg.installationKey, username, password))
                return c.json({ error: 'An owner already exists. Sign in.' }, 409);
        }
        else {
            cfg.installationKey = owner.installation_key;
            if (password || username !== owner.username) {
                if (password) {
                    const salt = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
                    await c.env.DB.prepare('UPDATE owner SET username=?,password_hash=?,salt=?,auth_generation=auth_generation+1 WHERE id=1').bind(username, await passwordHash(password, salt), salt).run();
                }
                else
                    await c.env.DB.prepare('UPDATE owner SET username=?,auth_generation=auth_generation+1 WHERE id=1').bind(username).run();
            }
        }
        cfg.jellyfin.password = '';
        cfg.revision = Date.now();
        const ctx = await buildCtx(cfg, c.env, new URL(c.req.url).origin);
        await registerAccount(ctx, true);
        c.header('Set-Cookie', setCookie(ctx.origin, await mintSession(c.env, c.req.raw, (await readOwner(c.env))!), SESSION_DAYS * 86400));
        return c.json({ config: publicConfig(cfg), token: await addonCapability(ctx), username });
    });
    router.post('/api/account/logout-all', async (c) => {
        if (!await ownerSession(c.env, c.req.raw))
            return c.json({ error: 'Sign in first.' }, 401);
        await c.env.DB!.prepare('UPDATE owner SET auth_generation=auth_generation+1 WHERE id=1').run();
        c.header('Set-Cookie', setCookie(new URL(c.req.url).origin, '', 0));
        return c.json({ ok: true });
    });
    router.post('/api/account/logout', async (c) => {
        if (!await ownerSession(c.env, c.req.raw))
            return c.json({ error: 'Sign in first.' }, 401);
        const payload = cookieValue(c.req.raw).split('.')[0];
        const { n } = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
        await stateDelete(sessionCtx(c.env, c.req.raw), `owner-session:${n}`);
        c.header('Set-Cookie', setCookie(new URL(c.req.url).origin, '', 0));
        return c.json({ ok: true });
    });
}
