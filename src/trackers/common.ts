import {limitedJson,limitedText} from '../security/limits';
import {safeFetch,addonHttpAllowed} from '../security/outbound';
import type { IdBundle } from '../meta/types';
import type { ContentType } from '../stremio/types';
import type { ResumeEntry, WatchSnapshot } from './types';

export function emptySnapshot(): WatchSnapshot {
  return { movies: [], episodes: [], shows: [], resume: [], fetchedAt: new Date().toISOString() };
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function clampPercent(n: unknown): number {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(100, v));
}

export function asInt(n: unknown): number | undefined {
  const v = Number(n);
  return Number.isFinite(v) && v > 0 ? Math.trunc(v) : undefined;
}

export function isoOrNow(v: unknown): string {
  if (typeof v === 'string' && !Number.isNaN(Date.parse(v))) return v;
  return nowIso();
}

export function epoch(v: string | undefined): number {
  if (!v) return 0;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : 0;
}

export function stremioIdOf(ids: IdBundle): string | null {
  if (ids.imdb) return ids.imdb;
  if (ids.tmdb) return `tmdb:${ids.tmdb}`;
  if (ids.tvdb) return `tvdb:${ids.tvdb}`;
  if (ids.mal) return `mal:${ids.mal}`;
  if (ids.anilist) return `anilist:${ids.anilist}`;
  if (ids.kitsu) return `kitsu:${ids.kitsu}`;
  if (ids.anidb) return `anidb:${ids.anidb}`;
  if (ids.tvmaze) return `tvmaze:${ids.tvmaze}`;
  return null;
}

export function titleKey(ids: IdBundle, kind: 'movie' | 'episode' | 'series', season?: number, episode?: number): string {
  const base = stremioIdOf(ids) ?? 'unknown';
  if (kind === 'episode') return `${base}:${season ?? 0}:${episode ?? 0}`;
  return base;
}

export function resumeKey(e: ResumeEntry): string {
  return titleKey(e.ids, e.kind, e.season, e.episode);
}

export function previewType(kind: 'movie' | 'series' | 'anime'): ContentType {
  return kind;
}

export interface WriteResult {
  status: number;
  ok: boolean;
  body: unknown;
}

export async function sendRequest(url: string, init: RequestInit & { timeoutMs?: number } = {}): Promise<WriteResult> {
  const { timeoutMs = 12000, ...rest } = init;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await safeFetch(url, { ...rest, signal: ctrl.signal });
    let body: unknown = null;
    const text = await limitedText(res);
    if (text) {
      try { body = JSON.parse(text); } catch { body = text; }
    }
    return { status: res.status, ok: res.ok, body };
  } catch {
    return { status: 0, ok: false, body: null };
  } finally {
    clearTimeout(timer);
  }
}

export async function fingerprint(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function newer(a: string | undefined, b: string | undefined): string {
  return epoch(a) >= epoch(b) ? (a ?? nowIso()) : (b ?? nowIso());
}
