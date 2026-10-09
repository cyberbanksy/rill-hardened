import type { Ctx } from '../context';
import { b64urlEncode, sha256 } from '../util/bytes';
import { statePut } from '../storage/state';
import { generation } from './auth';
export async function addonCapability(ctx: Ctx): Promise<string> {
    const token = 'r1.' + b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    await statePut(ctx, `addon-capability:${await sha256(token)}`, { scope: ctx.scope, g: await generation(ctx.env) }, 30 * 86400);
    return token;
}
