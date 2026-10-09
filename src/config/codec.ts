import { normalizeConfig, type RillConfig } from './schema';
import { b64urlDecode, b64urlEncode } from '../util/bytes';

import { readLimited } from '../security/limits';

const PREFIX = 'c1.';
const decoded = new Map<string, string>();

export async function encodeConfig(cfg: RillConfig): Promise<string> {
  const json = new TextEncoder().encode(JSON.stringify({...cfg,jellyfin:{...cfg.jellyfin,password:''}}));
  if(json.byteLength>262144)throw Error('Config exceeds byte limit');
  const cs = new CompressionStream('deflate-raw');
  const w = cs.writable.getWriter();
  void w.write(json); void w.close();
  const out = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  const token=PREFIX+b64urlEncode(out);
  if(token.length>65536)throw Error('Config exceeds encoded byte limit');
  return token;
}

export async function decodeConfig(token: string): Promise<RillConfig | null> {
  try {
    if(token.length>65536)return null;
    const cached = decoded.get(token);
    if (cached) return JSON.parse(cached) as RillConfig;
    let json: string;
    if (token.startsWith(PREFIX)) {
      const bytes = b64urlDecode(token.slice(PREFIX.length));
      const ds = new DecompressionStream('deflate-raw');
      const w = ds.writable.getWriter();
      void w.write(bytes).catch(()=>{}); void w.close().catch(()=>{});
      json = new TextDecoder().decode(await readLimited(ds.readable,262144));
    } else json = new TextDecoder().decode(b64urlDecode(token));
    if(new TextEncoder().encode(json).byteLength>262144)return null;
    const cfg = normalizeConfig(JSON.parse(json));
    cfg.jellyfin.password='';
    if (token.length <= 65536 && json.length <= 262144) {
      if (decoded.size >= 8) decoded.delete(decoded.keys().next().value!);
      decoded.set(token, JSON.stringify(cfg));
    }
    return cfg;
  } catch {
    return null;
  }
}
