import { AsyncLocalStorage } from 'node:async_hooks';
import { tryGetContext } from 'hono/context-storage';
import { IMAGE_LIMIT, limitStream, limitedJson } from './limits';
import type { Env } from '../env';
export function publicIp(raw: string): boolean {
    const ip = raw.replace(/^\[|\]$/g, '').toLowerCase();
    if (ip.includes(':')) {
        if (!/^[0-9a-f:]+$/.test(ip))
            return false;
        const halves = ip.split('::');
        if (halves.length > 2)
            return false;
        const left = halves[0] ? halves[0].split(':') : [], right = halves[1] ? halves[1].split(':') : [];
        const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
        if (words.length !== 8 || words.some(w => !w || w.length > 4))
            return false;
        const value = words.reduce((n, w) => (n << 16n) + BigInt(parseInt(w, 16)), 0n);
        const inRange = (base: bigint, bits: bigint) => (value >> (128n - bits)) === (base >> (128n - bits));
        if (!inRange(0x20000000000000000000000000000000n, 3n))
            return false;
        return !inRange(0x20010000000000000000000000000000n, 23n) && !inRange(0x20010db8000000000000000000000000n, 32n) && !inRange(0x20020000000000000000000000000000n, 16n) && !inRange(0x3fff0000000000000000000000000000n, 20n);
    }
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255))
        return false;
    const [a, b, c] = p;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && (b === 168 || b === 0 || b === 2 || b === 88 && c === 99) || a === 100 && b >= 64 && b <= 127 || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113);
}
export function validateDestination(raw: string, opts: {
    allowHttp?: boolean;
} = {}): URL {
    const u = new URL(raw);
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (u.protocol !== 'https:' && !(opts.allowHttp && u.protocol === 'http:'))
        throw Error('Outbound protocol denied');
    if (u.username || u.password || u.port && u.port !== '443' && !(opts.allowHttp && u.port === '80'))
        throw Error('Outbound authority denied');
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.invalid') || host.endsWith('.test') || host.endsWith('.home') || host.endsWith('.lan') || host === 'metadata.google.internal' || !host.includes('.') && !host.includes(':'))
        throw Error('Outbound host denied');
    if ((host.includes(':') || /^[\d.]+$/.test(host)) && !publicIp(host))
        throw Error('Outbound address denied');
    u.hostname = host;
    return u;
}
type Policy = {
    allowHttp?: boolean;
    resolve?: (host: string) => Promise<string[]>;
    fetcher?: typeof fetch;
    maxBytes?: number;
};
async function resolvePublic(host: string): Promise<string[]> {
    if (host.includes(':') || /^[\d.]+$/.test(host))
        return [host];
    const addresses: string[] = [];
    for (const type of ['A', 'AAAA']) {
        // Fixed HTTPS resolver bootstrap; never accepts a caller-supplied resolver URL.
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, { headers: { accept: 'application/dns-json' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
        if (!res.ok)
            throw Error('DNS lookup failed');
        const data = await limitedJson<{
            Status: number;
            Answer?: Array<{
                type: number;
                data: string;
            }>;
        }>(res, 65536);
        if (data.Status !== 0)
            throw Error('DNS lookup failed');
        for (const a of data.Answer ?? [])
            if (a.type === 1 || a.type === 28)
                addresses.push(a.data);
    }
    return addresses;
}
export async function safeFetch(raw: string, init: RequestInit = {}, policy: Policy = {}): Promise<Response> {
    const fetcher = policy.fetcher ?? fetch;
    let url = validateDestination(raw, { allowHttp: policy.allowHttp });
    let options: RequestInit = { ...init, redirect: 'manual', signal: init.signal ?? AbortSignal.timeout(15000) };
    for (let hop = 0; hop <= 5; hop++) {
        const ips = await (policy.resolve ?? resolvePublic)(url.hostname);
        if (!ips.length || ips.some(ip => !publicIp(ip)))
            throw Error('Outbound DNS address denied');
        const res = await fetcher(url.href, options);
        if ([301, 302, 303, 307, 308].includes(res.status)) {
            const location = res.headers.get('location');
            await res.body?.cancel();
            if (!location || hop === 5)
                throw Error('Outbound redirect denied');
            const next = validateDestination(new URL(location, url).href, { allowHttp: policy.allowHttp });
            if (next.origin !== url.origin) {
                // A credentialed request may not transfer its headers, body or URL secrets to another origin.
                if (options.body || Array.from(new Headers(options.headers).keys()).some(k => /authorization|cookie|key|token/i.test(k)))
                    throw Error('Credentialed cross-origin redirect denied');
                options = { ...options, headers: { accept: new Headers(options.headers).get('accept') ?? '*/*' } };
            }
            if (res.status === 303 || [301, 302].includes(res.status) && options.method === 'POST')
                options = { ...options, method: 'GET', body: undefined };
            url = next;
            continue;
        }
        const max = policy.maxBytes ?? IMAGE_LIMIT;
        const length = res.headers.get('content-length');
        if (length && Number(length) > max) {
            await res.body?.cancel();
            throw Error('Response exceeds byte limit');
        }
        return new Response(res.body ? limitStream(res.body, max) : null, { status: res.status, statusText: res.statusText, headers: res.headers });
    }
    throw Error('Outbound redirect denied');
}
const outboundHttp = new AsyncLocalStorage<boolean>();
export function withOutboundPolicy<T>(env: Env, work: () => Promise<T>): Promise<T> { return outboundHttp.run(env.ALLOW_HTTP_ADDONS === 'true', work); }
export function addonHttpAllowed(): boolean { return tryGetContext<{
    Bindings: Env;
}>()?.env.ALLOW_HTTP_ADDONS === 'true' || outboundHttp.getStore() === true; }
