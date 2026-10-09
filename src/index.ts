import {withOutboundPolicy} from './security/outbound';
import { Hono } from 'hono';
import { contextStorage } from 'hono/context-storage';
import type { Env, RillJob } from './env';
import { preparePresentation } from './jellyfin/presentation';
import type { Ctx } from './context';
import {loadConfig,migrateSecrets} from './security/secrets';
import {generation} from './security/auth';
import { sha256 } from './util/bytes';
import { addonRouter } from './addon/index';
import { handleJellyfinRequest, isJellyfinPath } from './jellyfin/index';
import { uiRouter } from './ui/index';
import { ensureSchema } from './storage/migrate';

type App = { Bindings: Env; Variables: { ctx: Ctx } };

const app = new Hono<App>();

app.use(contextStorage());

app.use('*', async (c, next) => {
  if (c.env.DB) {await ensureSchema(c.env.DB);await migrateSecrets(c.env);}
  await next();
  if(isJellyfinPath(new URL(c.req.url).pathname)||/^\/r1\.[A-Za-z0-9_-]{43}\//.test(new URL(c.req.url).pathname)) {
    c.res.headers.set('Access-Control-Allow-Origin','*');
    c.res.headers.set('Access-Control-Allow-Headers','Content-Type,Authorization,X-Emby-Authorization,X-Emby-Token,X-MediaBrowser-Token');
    c.res.headers.set('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  }

});
app.options('*', (c) => c.body(null, 204));

async function buildCtx(c:{req:{url:string;raw:Request};env:Env},token:string,savedScope?:string):Promise<Ctx|null> {
 if(!c.env.DB)return null;
 let scope=savedScope;
 if(!scope){
  if(!/^r1\.[A-Za-z0-9_-]{43}$/.test(token))return null;
  const row=await c.env.DB.prepare('SELECT value FROM state WHERE key=? AND expires>?').bind(`addon-capability:${await sha256(token)}`,Date.now()).first<{value:string}>();
  if(!row)return null;const value=JSON.parse(row.value);if(value.g!==await generation(c.env))return null;scope=value.scope;
 }
 const saved=await c.env.DB.prepare('SELECT config FROM accounts WHERE scope=?').bind(scope).first<{config:string}>();
 const cfg=saved?await loadConfig(saved.config,c.env,scope!):null;if(!cfg)return null;
 return {cfg,env:c.env,cfgToken:savedScope?'':token,origin:new URL(c.req.url).origin,scope:scope!,cacheRevision:(await sha256(JSON.stringify(cfg))).slice(0,16),lang:cfg.language.slice(0,2).toLowerCase(),tmdbKey:cfg.keys.tmdb||c.env.TMDB_KEY};
}

app.route('/', uiRouter);

app.use('*', async (c, next) => {
  if (!isJellyfinPath(new URL(c.req.url).pathname)) return next();
  if (!c.env.DB) return c.json({ Message: 'Save your server account before connecting.' }, 503);
  const owner = await c.env.DB.prepare('SELECT installation_key FROM owner WHERE id = 1').first<{ installation_key: string }>();
  if (!owner) return c.json({ Message: 'Set up your server account before connecting.' }, 503);
  const scope = (await sha256(owner.installation_key)).slice(0, 32);
  const saved = await c.env.DB.prepare('SELECT config FROM accounts WHERE scope=?').bind(scope).first<{ config: string }>();
  const ctx = saved ? await buildCtx(c, '', scope) : null;
  if (!ctx || ctx.scope !== scope) return c.json({ Message: 'Server configuration is unavailable.' }, 503);
  let exec: Parameters<typeof handleJellyfinRequest>[3];
  try { exec = c.executionCtx; } catch {}
  return handleJellyfinRequest(ctx, c.req.raw, c.env, exec);
});

app.use('/:cfg/*', async (c, next) => {
  const ctx = await buildCtx(c, c.req.param('cfg'));
  if (!ctx) return c.json({ error: 'bad config' }, 400);
  try {
    const exec = c.executionCtx;
    ctx.defer = work => exec.waitUntil(work.catch(() => console.warn('Background work failed')));
  } catch {}
  c.set('ctx', ctx);
  await next();
});
app.route('/:cfg', addonRouter);

app.notFound((c) => c.json({ error: 'not found' }, 404));
app.onError((err, c) => {
  console.error('Request failed');
  return c.json({ error: 'internal' }, 500);
});

import { hasScheduledWork, scheduled } from './storage/scheduled';
export default {
  fetch: app.fetch,
  async scheduled(event:ScheduledController,env:Env):Promise<void> {
    if(env.RILL_JOBS) {
      // Keep idle maintenance from consuming the free daily Queue allowance.
      if(Math.floor(event.scheduledTime/60_000)%30===0 || await hasScheduledWork(env,event.scheduledTime)) {
        await env.RILL_JOBS.send({kind:'maintenance',scheduledTime:event.scheduledTime});
      }
    }
    else await withOutboundPolicy(env,()=>scheduled(event,env));
  },
  async queue(batch:MessageBatch<RillJob>,env:Env):Promise<void> {
    if(env.DB){await ensureSchema(env.DB);await migrateSecrets(env);}
    for(const message of batch.messages) {
      if(message.body.kind==='maintenance')await withOutboundPolicy(env,()=>scheduled({scheduledTime:(message.body as {scheduledTime:number}).scheduledTime,cron:'* * * * *',noRetry(){}} as ScheduledController,env));
      else if(message.body.kind==='presentation')await withOutboundPolicy(env,()=>preparePresentation(message.body as import('./jellyfin/presentation').PresentationJob,env));
      message.ack();
    }
  },
};
