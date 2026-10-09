import {seal,unseal} from '../security/secrets';
import type { Ctx } from '../context';
import type { MalAuth, TraktAuth } from '../config/schema';
import { sendRequest } from '../trackers/common';
import { cleanupDatabase } from './budget';

type Service = 'trakt' | 'mal';
type Auth = TraktAuth | MalAuth;
const expires = (a: Auth) => a.expiresAt ? (a.expiresAt < 1e12 ? a.expiresAt * 1000 : a.expiresAt) : Infinity;

const reads=new WeakMap<Ctx,Map<Service,Promise<Auth>>>();
export function credentials<T extends Auth>(ctx:Ctx,service:Service,initial:T):Promise<T> {
  let services=reads.get(ctx);if(!services){services=new Map();reads.set(ctx,services);}
  let task=services.get(service);
  if(!task){task=loadCredentials(ctx,service,initial);services.set(service,task);task.catch(()=>services!.delete(service));}
  return task as Promise<T>;
}
async function loadCredentials<T extends Auth>(ctx: Ctx, service: Service, initial: T): Promise<T> {
  const db = ctx.env.DB;
  if (!db) return initial;
  await db.prepare('INSERT INTO credentials(scope,service,value) VALUES(?,?,?) ON CONFLICT(scope,service) DO NOTHING')
    .bind(ctx.scope,service,await seal(JSON.stringify(initial),ctx.env,`credential:${ctx.scope}:${service}`)).run();
  const row = await db.prepare('SELECT value FROM credentials WHERE scope=? AND service=?').bind(ctx.scope,service).first<{value:string}>();
  const current = JSON.parse(await unseal(row!.value,ctx.env,`credential:${ctx.scope}:${service}`)) as T;
  if (expires(current) > Date.now()+300_000 || !current.refreshToken) return current;
  const lease = crypto.randomUUID();
  const locked = await db.prepare('UPDATE credentials SET lease=?,lease_until=? WHERE scope=? AND service=? AND lease_until<=? AND value=? RETURNING value')
    .bind(lease,Date.now()+60_000,ctx.scope,service,Date.now(),row!.value).first();
  if (!locked) throw new Error('Credential refresh in progress');
  try {
    let url: string, init: RequestInit;
    if (service === 'trakt') {
      const a = current as TraktAuth;
      if (!a.clientSecret) throw new Error('Trakt refresh requires client secret');
      url = 'https://api.trakt.tv/oauth/token';
      init = { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ client_id:a.clientId,client_secret:a.clientSecret,refresh_token:a.refreshToken,grant_type:'refresh_token',redirect_uri:'urn:ietf:wg:oauth:2.0:oob' }) };
    } else {
      url = 'https://myanimelist.net/v1/oauth2/token';
      const body = new URLSearchParams({ client_id:current.clientId,refresh_token:current.refreshToken!,grant_type:'refresh_token' });
      if ('clientSecret' in current && current.clientSecret) body.set('client_secret',String(current.clientSecret));
      init = { method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body.toString() };
    }
    const response = await sendRequest(url,init);
    const value = response.body as {access_token?:string;refresh_token?:string;expires_in?:number};
    if (!response.ok || !value?.access_token || !Number.isFinite(value.expires_in) || Number(value.expires_in)<=0) throw new Error('Credential refresh rejected');
    const updated = { ...current,accessToken:value.access_token,refreshToken:value.refresh_token || current.refreshToken,expiresAt:Date.now()+Number(value.expires_in)*1000 };
    const saved = await db.prepare('UPDATE credentials SET value=?,lease=NULL,lease_until=0 WHERE scope=? AND service=? AND lease=?')
      .bind(await seal(JSON.stringify(updated),ctx.env,`credential:${ctx.scope}:${service}`),ctx.scope,service,lease).run();
    if (!saved.meta.changes) throw new Error('Credential refresh lease lost');
    return updated;
  } catch (error) {
    await cleanupDatabase(db).prepare('UPDATE credentials SET lease=NULL,lease_until=0 WHERE scope=? AND service=? AND lease=?').bind(ctx.scope,service,lease).run();
    throw error;
  }
}
