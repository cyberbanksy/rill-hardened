import type { Env } from '../env';
import { b64urlDecode, b64urlEncode } from '../util/bytes';
import { decodeConfig, encodeConfig } from '../config/codec';
import { normalizeConfig, type RillConfig } from '../config/schema';
const PREFIX = 'e1.';
async function dataKey(env: Env): Promise<CryptoKey> {
    if (!env.RILL_DATA_KEY)
        throw Error('RILL_DATA_KEY is required');
    const bytes = b64urlDecode(env.RILL_DATA_KEY.trim().replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    if (bytes.length !== 32)
        throw Error('RILL_DATA_KEY must contain 32 random bytes in base64');
    return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function seal(value: string, env: Env, aad: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad) }, await dataKey(env), new TextEncoder().encode(value));
    return PREFIX + b64urlEncode(iv) + '.' + b64urlEncode(new Uint8Array(ciphertext));
}
export async function unseal(value: string, env: Env, aad: string): Promise<string> {
    if (!value.startsWith(PREFIX))
        throw Error('Unencrypted stored credential');
    const [iv, ciphertext] = value.slice(3).split('.');
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlDecode(iv), additionalData: new TextEncoder().encode(aad) }, await dataKey(env), b64urlDecode(ciphertext)));
}
export async function storeConfig(cfg: RillConfig, env: Env, scope: string): Promise<string> { return seal(await encodeConfig(cfg), env, `config:${scope}`); }
export async function loadConfig(value: string, env: Env, scope: string): Promise<RillConfig | null> {
    return decodeConfig(value.startsWith(PREFIX) ? await unseal(value, env, `config:${scope}`) : value);
}
// Secrets are write-only in the settings UI. Empty/masked values preserve server values.
export const SAVED = '__RILL_SAVED__';
const hidden = (v: unknown) => v ? SAVED : '';
export function addonReference(value: string, cfg: RillConfig): string { return /^saved-addon:\d+$/.test(value) ? Array.from(new Set(Object.values(cfg.addons).flat()))[Number(value.split(':')[1])] ?? '' : value; }
export function publicConfig(cfg: RillConfig): RillConfig {
    const out = structuredClone(cfg);
    out.installationKey = '';
    out.jellyfin.password = '';
    for (const key of Object.keys(out.keys))
        (out.keys as Record<string, string>)[key] = hidden((out.keys as Record<string, string>)[key]);
    for (const service of ['trakt', 'simkl', 'mal', 'anilist']) {
        const auth = (out.trackers as unknown as Record<string, Record<string, unknown>>)[service];
        if (auth)
            for (const key of Object.keys(auth))
                if (/token|secret|key|password/i.test(key))
                    auth[key] = hidden(auth[key]);
    }
    const references = Array.from(new Set(Object.values(cfg.addons).flat()));
    for (const list of Object.values(out.addons))
        if (Array.isArray(list))
            for (let i = 0; i < list.length; i++)
                if (typeof list[i] === 'string')
                    list[i] = `saved-addon:${references.indexOf(list[i])}`;
    if (out.recommendations)
        out.recommendations.apiKey = hidden(out.recommendations.apiKey);
    if (out.movieLens)
        out.movieLens.password = hidden(out.movieLens.password);
    return out;
}
export function mergePrivate(input: unknown, saved: RillConfig): RillConfig {
    const cfg = normalizeConfig(input);
    cfg.installationKey = saved.installationKey;
    for (const key of Object.keys(saved.keys))
        if (!(cfg.keys as Record<string, string>)[key] || (cfg.keys as Record<string, string>)[key] === SAVED)
            (cfg.keys as Record<string, string>)[key] = (saved.keys as Record<string, string>)[key];
    for (const service of ['trakt', 'simkl', 'mal', 'anilist']) {
        const before = (saved.trackers as unknown as Record<string, Record<string, unknown>>)[service], next = (cfg.trackers as unknown as Record<string, Record<string, unknown>>)[service];
        if (before && next)
            for (const key of Object.keys(before))
                if (/token|secret|key|password/i.test(key) && (!next[key] || next[key] === SAVED))
                    next[key] = before[key];
    }
    for (const [kind, list] of Object.entries(cfg.addons))
        if (Array.isArray(list))
            for (let i = 0; i < list.length; i++)
                if (typeof list[i] === 'string' && /^saved-addon:\d+$/.test(list[i]))
                    list[i] = addonReference(list[i], saved);
    if (cfg.recommendations && (!cfg.recommendations.apiKey || cfg.recommendations.apiKey === SAVED))
        cfg.recommendations.apiKey = saved.recommendations?.apiKey ?? '';
    if (cfg.movieLens && (!cfg.movieLens.password || cfg.movieLens.password === SAVED))
        cfg.movieLens.password = saved.movieLens?.password ?? '';
    return cfg;
}
const migrations = new WeakMap<D1Database, Promise<void>>();
export function migrateSecrets(env: Env): Promise<void> {
    if (!env.DB || !env.RILL_DATA_KEY)
        return Promise.resolve();
    let task = migrations.get(env.DB);
    if (!task) {
        task = convert(env).catch(e => { migrations.delete(env.DB!); throw e; });
        migrations.set(env.DB, task);
    }
    return task;
}
async function convert(env: Env): Promise<void> {
    const db = env.DB!;
    if (await db.prepare("SELECT 1 FROM state WHERE key='hardening:encrypted-v1'").first())
        return;
    // Remove orphan durable jobs/accounts admitted by the former public helper.
    const owner = await db.prepare('SELECT installation_key FROM owner WHERE id=1').first<{
        installation_key: string;
    }>();
    if (owner) {
        const { sha256 } = await import('../util/bytes');
        const scope = (await sha256(owner.installation_key)).slice(0, 32);
        await db.batch([db.prepare('DELETE FROM recommendation_jobs WHERE scope<>?').bind(scope), db.prepare('DELETE FROM accounts WHERE scope<>?').bind(scope)]);
    }
    // Idempotent compare-and-swap: concurrent first requests cannot overwrite newer saves.
    for (const table of ['accounts', 'recommendation_jobs']) {
        const rows = await db.prepare(`SELECT rowid,scope,config FROM ${table} WHERE config NOT LIKE 'e1.%'`).all<{
            rowid: number;
            scope: string;
            config: string;
        }>();
        for (const row of rows.results) {
            const cfg = await decodeConfig(row.config);
            if (!cfg)
                throw Error('Invalid legacy config');
            cfg.jellyfin.password = '';
            await db.prepare(`UPDATE ${table} SET config=? WHERE rowid=? AND config=?`).bind(await storeConfig(cfg, env, row.scope), row.rowid, row.config).run();
        }
    }
    await db.prepare("DELETE FROM credentials WHERE service IN ('update','updates','cloudflare','update-monitor') OR scope='install'").run();
    const rows = await db.prepare("SELECT scope,service,value FROM credentials WHERE value NOT LIKE 'e1.%'").all<{
        scope: string;
        service: string;
        value: string;
    }>();
    for (const row of rows.results)
        await db.prepare('UPDATE credentials SET value=? WHERE scope=? AND service=? AND value=?').bind(await seal(row.value, env, `credential:${row.scope}:${row.service}`), row.scope, row.service, row.value).run();
    const signing = await db.prepare("SELECT value FROM state WHERE key='install:signing-key'").first<{
        value: string;
    }>();
    if (signing && !signing.value.startsWith('e1.'))
        await db.prepare("UPDATE state SET value=? WHERE key='install:signing-key' AND value=?").bind(await seal(signing.value, env, 'state:install:signing-key'), signing.value).run();
    // Legacy cache keys contain URLs; flush persisted caches, old hooks and monitor state.
    await db.batch([db.prepare('DELETE FROM image_tags'), db.prepare('DELETE FROM presentations')]);
    await db.prepare("DELETE FROM state WHERE key LIKE 'cache:%' OR key LIKE '%update%' OR key LIKE 'movielens:session:%' OR key LIKE 'jf-image:v1:%' OR key LIKE 'recommendations:%' OR key LIKE 'taste:%'").run();
    await db.prepare("INSERT OR IGNORE INTO state(key,value,expires) VALUES('hardening:encrypted-v1','true',?)").bind(Date.now() + 100 * 365 * 86400000).run();
}
