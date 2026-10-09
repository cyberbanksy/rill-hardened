import {limitedJson,limitedText} from '../../security/limits';
import {safeFetch,addonHttpAllowed} from '../../security/outbound';
import type { Ctx } from '../../context';
import { memo } from '../../util/cache';
export type EpisodeSpace = 'tvdb' | 'tmdb';
export interface EpisodeRule { animeSeason: number; season: number; start?: number; end?: number; offset: number; pairs: Array<[number, number[]]> }
export interface EpisodeMap { anidb: number; tvdb?: number; tmdb?: number; tvdbSeason?: number; tmdbSeason?: number; tvdbOffset: number; tmdbOffset: number; tvdbRules: EpisodeRule[]; tmdbRules: EpisodeRule[] }
export interface AnimeEpisode { anidb: number; season: number; episode: number }
export interface ExternalEpisode { id: number; season: number; episode: number }
const URL = 'https://raw.githubusercontent.com/Anime-Lists/anime-lists/refs/heads/master/anime-list-full.xml';
const integer = (v: string | undefined): number | undefined => v !== undefined && /^-?\d+$/.test(v) ? Number(v) : undefined;
function attrs(text: string): Record<string, string> {
  return Object.fromEntries([...text.matchAll(/([a-z]+)\s*=\s*["']([^"']*)["']/g)].map(m => [m[1], m[2]]));
}
export function parseEpisodeMaps(xml: string): EpisodeMap[] {
  const out: EpisodeMap[] = [];
  for (const match of xml.replace(/<!--[\s\S]*?-->/g, '').matchAll(/<anime\s+([^>]+?)(?:\/>|>([\s\S]*?)<\/anime>)/g)) {
    const a = attrs(match[1]);
    const anidb = integer(a.anidbid), tvdb = integer(a.tvdbid), tmdb = integer(a.tmdbtv);
    if (!anidb || (!tvdb && !tmdb)) continue;
    const row: EpisodeMap = { anidb, tvdb, tmdb, tvdbSeason: integer(a.defaulttvdbseason), tmdbSeason: integer(a.tmdbseason), tvdbOffset: integer(a.episodeoffset) ?? 0, tmdbOffset: integer(a.tmdboffset) ?? 0, tvdbRules: [], tmdbRules: [] };
    for (const m of (match[2]??'').matchAll(/<mapping\s+([^>]*?)(?:\/>|>([\s\S]*?)<\/mapping>)/g)) {
      const b = attrs(m[1]);
      const pairs: EpisodeRule['pairs'] = [];
      for (const pair of (m[2] ?? '').split(';')) {
        const p = /^\s*(\d+)-(\d+(?:\+\d+)*)\s*$/.exec(pair);
        if (p) pairs.push([Number(p[1]), p[2].split('+').map(Number)]);
      }
      for (const space of ['tvdb', 'tmdb'] as const) {
        const season = integer(b[`${space}season`]);
        const animeSeason = integer(b.anidbseason);
        if (season === undefined || animeSeason === undefined) continue;
        row[`${space}Rules`].push({ animeSeason, season, start: integer(b.start), end: integer(b.end), offset: integer(b.offset) ?? 0, pairs });
      }
    }
    out.push(row);
  }
  return out;
}
function unique<T>(rows: T[]): T[] { return [...new Map(rows.map(r => [JSON.stringify(r), r])).values()]; }
export function toExternalEpisodes(rows: EpisodeMap[], space: EpisodeSpace, anime: AnimeEpisode): ExternalEpisode[] {
  const row = rows.find(r => r.anidb === anime.anidb);
  if (!row || !row[space] || anime.episode < 1) return [];
  const id = row[space]!;
  const rules = row[`${space}Rules`].filter(r => r.animeSeason === anime.season);
  const explicit = rules.flatMap(r => r.pairs.filter(p => p[0] === anime.episode).flatMap(p => p[1].map(episode => ({ id, season: r.season, episode }))));
  if (explicit.length) return unique(explicit.filter(r => r.episode > 0));
  const ranges = rules.filter(r => r.start !== undefined && anime.episode >= r.start && (r.end === undefined || anime.episode <= r.end));
  if (ranges.length) return unique(ranges.map(r => ({ id, season: r.season, episode: anime.episode + r.offset })).filter(r => r.episode > 0));
  const season = row[`${space}Season`];
  if (anime.season !== 1 || season === undefined || season === 0) return [];
  const offset = row[`${space}Offset`], episode = anime.episode + offset;
  const next = rows.filter(r => r[space] === id && r[`${space}Season`] === season && r[`${space}Offset`] > offset).map(r => r[`${space}Offset`]).sort((a,b) => a-b)[0];
  if (episode <= 0 || (next !== undefined && episode > next)) return [];
  if (rows.some(r => r.anidb !== row.anidb && r[space] === id && r[`${space}Season`] === season && r[`${space}Offset`] === offset)) return [];
  return [{ id, season, episode }];
}
export function toAnimeEpisodes(rows: EpisodeMap[], space: EpisodeSpace, external: ExternalEpisode): AnimeEpisode[] {
  const matches: AnimeEpisode[] = [];
  for (const row of rows.filter(r => r[space] === external.id)) {
    const candidates: AnimeEpisode[] = [];
    for (const rule of row[`${space}Rules`].filter(r => r.season === external.season)) {
      for (const [episode, targets] of rule.pairs) if (targets.includes(external.episode)) candidates.push({ anidb: row.anidb, season: rule.animeSeason, episode });
      const episode = external.episode - rule.offset;
      if (rule.start !== undefined && episode >= rule.start && (rule.end === undefined || episode <= rule.end)) candidates.push({ anidb: row.anidb, season: rule.animeSeason, episode });
    }
    if (row[`${space}Season`] === external.season) candidates.push({ anidb: row.anidb, season: 1, episode: external.episode - row[`${space}Offset`] });
    for (const candidate of candidates) if (toExternalEpisodes(rows, space, candidate).some(r => r.id === external.id && r.season === external.season && r.episode === external.episode)) matches.push(candidate);
  }
  return unique(matches);
}
const requests = new WeakMap<Ctx, Promise<EpisodeMap[]>>();
export function loadEpisodeMaps(ctx: Ctx): Promise<EpisodeMap[]> {
  let task = requests.get(ctx);
  if (!task) {
    task = memo('anime:episode-map:v1', 86400, async () => {
      const res = await safeFetch(URL, { signal: AbortSignal.timeout(15000) });
      if (!res.ok) throw new Error('Episode mapping source unavailable');
      const xml = await limitedText(res);
      if (xml.length > 8_000_000) throw new Error('Episode mapping source too large');
      const rows = parseEpisodeMaps(xml);
      if (!rows.length) throw new Error('Episode mapping source invalid');
      return rows;
    });
    requests.set(ctx, task);
  }
  return task;
}
