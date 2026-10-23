import type { Env } from '../env';
import { b64urlEncode, hmac, sha256, timingSafeEqual } from '../util/bytes';
export interface OwnerRow {
    installation_key: string;
    username: string;
    password_hash: string;
    salt: string;
    auth_generation: number;
}
export async function readOwner(env: Env): Promise<OwnerRow | null> { return env.DB ? env.DB.prepare('SELECT installation_key,username,password_hash,salt,auth_generation FROM owner WHERE id=1').first<OwnerRow>() : null; }
export async function passwordHash(password: string, salt: string): Promise<string> {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    return b64urlEncode(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256)));
}
export async function verifyPassword(owner: OwnerRow, password: unknown): Promise<boolean> { return typeof password === 'string' && password.length <= 1024 && timingSafeEqual(await passwordHash(password, owner.salt), owner.password_hash); }
export async function generation(env: Env): Promise<number> { return (await readOwner(env))?.auth_generation ?? 0; }
export async function claimOwner(env: Env, installation: string, username: string, password: string): Promise<boolean> {
    const salt = b64urlEncode(crypto.getRandomValues(new Uint8Array(16))), hash = await passwordHash(password, salt);
    const result = await env.DB!.prepare('INSERT OR IGNORE INTO owner(id,installation_key,username,password_hash,salt,created) VALUES(1,?,?,?,?,?)').bind(installation, username, hash, salt, Date.now()).run();
    return result.meta.changes === 1;
}
export function readCookie(req: Request, name: string): string { return req.headers.get('cookie')?.split(';').map(p => p.trim()).find(p => p.startsWith(name + '='))?.slice(name.length + 1) ?? ''; }
// A browser that signed in before gets its own throttle bucket, so others' failed guesses can't lock it out.
const DEVICE_DAYS = 180;
const deviceCookie = (url: string) => url.startsWith('https:') ? '__Host-rill_device' : 'rill_device';
async function deviceSecret(env: Env): Promise<string | null> { return env.RILL_DATA_KEY ? hmac(env.RILL_DATA_KEY, 'rill:device-cookie:v1') : null; }
// Signed with auth_generation, so a password change or logout-all invalidates it.
export async function trustedDevice(env: Env, req: Request): Promise<string | null> {
    const secret = await deviceSecret(env), [id, exp, g, sig] = readCookie(req, deviceCookie(req.url)).split('.');
    if (!secret || !id || !exp || !g || !sig || !/^[A-Za-z0-9_-]{22}$/.test(id) || !(Number(exp) > Date.now()))
        return null;
    if (!timingSafeEqual(await hmac(secret, `${id}.${exp}.${g}`), sig) || Number(g) !== await generation(env))
        return null;
    return id;
}
export async function deviceSetCookie(env: Env, req: Request): Promise<string | null> {
    const secret = await deviceSecret(env);
    if (!secret)
        return null;
    const id = b64urlEncode(crypto.getRandomValues(new Uint8Array(16))), exp = Date.now() + DEVICE_DAYS * 86400000, g = await generation(env);
    return `${deviceCookie(req.url)}=${id}.${exp}.${g}.${await hmac(secret, `${id}.${exp}.${g}`)}; Path=/; Max-Age=${DEVICE_DAYS * 86400}; HttpOnly; SameSite=Strict${req.url.startsWith('https:') ? '; Secure' : ''}`;
}
type Bucket = { key: string; free: number; maxShift: number; cap: number };
// The shared account bucket only slows distributed guessing; it starts late and stays short so nobody can hold it shut.
async function throttleKeys(env: Env, req: Request): Promise<Bucket[]> {
    const device = await trustedDevice(env, req);
    if (device)
        return [{ key: `device:${device}`, free: 4, maxShift: 8, cap: 300000 }];
    return [{ key: `ip:${await sha256(req.headers.get('cf-connecting-ip') ?? 'unknown')}`, free: 4, maxShift: 8, cap: 300000 }, { key: 'account:owner', free: 19, maxShift: 5, cap: 30000 }];
}
export async function loginThrottle(env: Env, req: Request): Promise<number> {
    if (!env.DB)
        return 60;
    const admission = crypto.randomUUID(), now = Date.now(), keys = await throttleKeys(env, req);
    // Count attempts before hashing. Each UPSERT is atomic, including concurrent bad guesses.
    const rows = await env.DB.batch(keys.map(({ key, free, maxShift, cap }) => env.DB!.prepare(`INSERT INTO login_limits(key,failures,window_start,blocked_until,admission) VALUES(?,1,?,0,?)
 ON CONFLICT(key) DO UPDATE SET
 admission=CASE WHEN window_start<? OR blocked_until<=? THEN excluded.admission ELSE admission END,
 failures=CASE WHEN window_start<? THEN 1 WHEN blocked_until>? THEN failures ELSE failures+1 END,
 window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END,
 blocked_until=CASE WHEN window_start<? THEN 0 WHEN blocked_until>? THEN blocked_until WHEN failures>=? THEN ?+min(?,1000*(1 << min(?,failures-?))) ELSE 0 END
 RETURNING blocked_until,admission`).bind(key, now, admission, now - 900000, now, now - 900000, now, now - 900000, now - 900000, now, free, now, cap, maxShift, free)));
    return Math.max(0, ...rows.map(r => { const row = r.results[0] as {
        blocked_until: number;
        admission: string;
    }; return row?.admission === admission ? 0 : Math.ceil((Number(row?.blocked_until ?? 0) - now) / 1000); }));
}
export async function resetLogin(env: Env, req: Request): Promise<void> {
    if (!env.DB)
        return;
    const keys = await throttleKeys(env, req);
    await env.DB.batch(keys.map(({ key }) => env.DB!.prepare('DELETE FROM login_limits WHERE key=?').bind(key)));
}
export async function helperQuota(env: Env, scope: string, kind: string, max = 60, window = 60000): Promise<boolean> {
    if (!env.DB)
        return false;
    const now = Date.now();
    const row = await env.DB.prepare(`INSERT INTO helper_limits(key,count,window_start) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END WHERE window_start<? OR count<? RETURNING count`).bind(`${scope}:${kind}`, now, now - window, now - window, now - window, max).first();
    return Boolean(row);
}
