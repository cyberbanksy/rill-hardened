import type { PresentationJob } from './jellyfin/presentation';

export type RillJob = {kind:'maintenance'; scheduledTime:number} | PresentationJob;

export interface Env {
  DB?: D1Database;
  RILL_SECRET?: string;
  TMDB_KEY?: string;
  D1_QUERY_BUDGET?: string;
  RILL_DATA_KEY?: string;
  RILL_SETUP_TOKEN?: string;
  ALLOW_HTTP_ADDONS?: string;
  RILL_JOBS?: Queue<RillJob>;
}
