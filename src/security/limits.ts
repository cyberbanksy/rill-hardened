export const JSON_LIMIT = 4 * 1024 * 1024;
export const IMAGE_LIMIT = 8 * 1024 * 1024;
export const SUBTITLE_LIMIT = 2 * 1024 * 1024;
export function limitStream(stream: ReadableStream<Uint8Array>, max: number): ReadableStream<Uint8Array> {
    let size = 0;
    return stream.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({ transform(chunk, controller) {
            size += chunk.byteLength;
            if (size > max)
                throw new Error('Response exceeds byte limit');
            controller.enqueue(chunk);
        } }));
}
export async function readLimited(stream: ReadableStream<Uint8Array> | null, max: number): Promise<Uint8Array> {
    if (!stream)
        return new Uint8Array();
    return new Uint8Array(await new Response(limitStream(stream, max)).arrayBuffer());
}
export async function limitedText(res: {
    body: ReadableStream<Uint8Array> | null;
}, max = JSON_LIMIT): Promise<string> { return new TextDecoder().decode(await readLimited(res.body, max)); }
export async function limitedJson<T = any>(res: {
    body: ReadableStream<Uint8Array> | null;
}, max = JSON_LIMIT): Promise<T> { return JSON.parse(await limitedText(res, max)) as T; }
export function rasterType(raw: string, bytes: Uint8Array): string | null {
    const mime = raw.split(';')[0].trim().toLowerCase();
    const starts = (sig: number[]) => sig.every((n, i) => bytes[i] === n);
    if (mime === 'image/png' && starts([137, 80, 78, 71, 13, 10, 26, 10]))
        return mime;
    if (mime === 'image/jpeg' && starts([255, 216, 255]))
        return mime;
    if (mime === 'image/gif' && /^GIF8[79]a$/.test(new TextDecoder().decode(bytes.slice(0, 6))))
        return mime;
    if (mime === 'image/webp' && new TextDecoder().decode(bytes.slice(0, 4)) === 'RIFF' && new TextDecoder().decode(bytes.slice(8, 12)) === 'WEBP')
        return mime;
    return null;
}
export const MEDIA_HEADERS = { 'Content-Security-Policy': 'sandbox', 'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'inline' };
