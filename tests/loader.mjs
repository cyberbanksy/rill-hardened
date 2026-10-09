import ts from 'typescript';
import { readFile } from 'node:fs/promises';
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('.') && context.parentURL) {
    const url = new URL(specifier, context.parentURL);
    if (!/\.[a-z]+$/.test(url.pathname)) {
      for (const suffix of ['.ts', '/index.ts']) {
        try { await readFile(new URL(url.href + suffix)); return {url:url.href+suffix,shortCircuit:true}; } catch {}
      }
    }
  }
  return next(specifier, context);
}
export async function load(url, context, next) {
  if(url.endsWith('.bin'))return {format:'module',source:`export default Uint8Array.from(${JSON.stringify(Array.from(await readFile(new URL(url))))}).buffer`,shortCircuit:true};
  if (url.endsWith('.sql')) return {format:'module',source:`export default ${JSON.stringify(await readFile(new URL(url),'utf8'))}`,shortCircuit:true};
  if (url.endsWith('.ts')) return {format:'module',source:ts.transpileModule(await readFile(new URL(url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,shortCircuit:true};
  return next(url,context);
}
