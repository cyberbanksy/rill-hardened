import {seal,unseal} from '../security/secrets';
import { createHash, createHmac } from 'node:crypto';
import type { Ctx } from '../context';

const remembered = new WeakMap<D1Database, Map<string, number>>();
const tagsByKey = new Map<string, Map<string, string>>();

// Keyed tags can't be computed from a public URL; unkeyed ones are only used as cache keys and ETags.
export function artworkTag(url: string, dataKey = ''): string {
  let tags = tagsByKey.get(dataKey);
  if (!tags) {
    if (tagsByKey.size >= 4) tagsByKey.clear();
    tags = new Map();
    tagsByKey.set(dataKey, tags);
  }
  let tag = tags.get(url);
  if (!tag) {
    tag = dataKey
      ? createHmac('sha256', createHmac('sha256', dataKey).update('rill:image-tag:v2').digest()).update(url).digest('hex').slice(0, 32)
      : createHash('md5').update(url).digest('hex');
    if (tags.size >= 4096) tags.delete(tags.keys().next().value!);
    tags.set(url, tag);
  }
  return tag;
}

function mappingKey(ctx: Ctx, tag: string): string {
  return `jf-image:v1:${ctx.scope}:${tag}`;
}

/** Convert only public image-tag fields; cached internal DTOs retain their URLs. */
export async function imageTaggedJson(ctx: Ctx, body: unknown, replacer: (key: string, value: unknown) => unknown): Promise<string> {
  const mappings = new Map<string, string>();
  const tagOf = (value: unknown): unknown => {
    if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return value;
    const tag = artworkTag(value, ctx.env.RILL_DATA_KEY);
    mappings.set(tag, value);
    return tag;
  };
  const json = JSON.stringify(body, (key, value) => {
    if (key === 'ImageTags' && value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([type, url]) => [type, tagOf(url)]));
    }
    if (key.endsWith('ImageTags') && Array.isArray(value)) return value.map(tagOf);
    if (key.endsWith('ImageTag')) return tagOf(value);
    return replacer(key, value);
  });
  if (mappings.size && ctx.env.DB) {
    let known = remembered.get(ctx.env.DB);
    if (!known) { known = new Map(); remembered.set(ctx.env.DB, known); }
    const now = Date.now();
    const rows = [...mappings].filter(([tag]) => (known.get(tag) ?? 0) <= now);
    // One write for the whole response, persisted before clients can request images.
    if (rows.length) {
      await ctx.env.DB.prepare(`INSERT INTO image_tags(tag,url,created)
        SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),? FROM json_each(?) WHERE 1
        ON CONFLICT(tag) DO NOTHING`)
        .bind(now, JSON.stringify(await Promise.all(rows.map(async([tag,url])=>[tag,await seal(url,ctx.env,`image-tag:${tag}`)])))).run();
      for (const [tag] of rows) {
        if (known.size >= 4096) known.delete(known.keys().next().value!);
        known.set(tag, now + 3600_000);
      }
    }
  }
  return json;
}

export async function imageUrlByTag(ctx: Ctx, tag: string | undefined): Promise<string | null> {
  if (!tag || !/^[a-f0-9]{32}$/i.test(tag)) return null;
  const row = await ctx.env.DB?.prepare('SELECT url FROM image_tags WHERE tag=? UNION ALL SELECT value FROM state WHERE key=? AND expires>? LIMIT 1')
    .bind(tag.toLowerCase(), mappingKey(ctx, tag.toLowerCase()), Date.now()).first<{url: string}>();
  if(!row||!row.url.startsWith('e1.'))return null;
  const url=await unseal(row.url,ctx.env,`image-tag:${tag.toLowerCase()}`);return /^https?:\/\//i.test(url)?url:null;
}
