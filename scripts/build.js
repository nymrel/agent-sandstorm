/**
 * @file build.js
 * @description Fast ESM build & type declaration generator for @nymrel/agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const srcDir = path.join(rootDir, 'src');
const distDir = path.join(rootDir, 'dist');

function cleanAndBuild() {
  console.log('Building @nymrel/agent-sandstorm (ESM + Types)...');
  fs.mkdirSync(distDir, { recursive: true });

  const files = getAllFiles(srcDir);
  let builtCount = 0;

  for (const srcFile of files) {
    if (!srcFile.endsWith('.ts')) continue;

    const relPath = path.relative(srcDir, srcFile);
    const destJs = path.join(distDir, relPath.replace(/\.ts$/, '.js'));
    const destDts = path.join(distDir, relPath.replace(/\.ts$/, '.d.ts'));

    fs.mkdirSync(path.dirname(destJs), { recursive: true });

    const tsCode = fs.readFileSync(srcFile, 'utf-8');
    const jsCode = stripTypeScript(tsCode);

    fs.writeFileSync(destJs, jsCode, 'utf-8');
    fs.writeFileSync(destDts, tsCode, 'utf-8');
    builtCount++;
  }

  console.log(`✅ Build completed: ${builtCount} modules compiled to dist/`);
}

function getAllFiles(dir) {
  const result = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...getAllFiles(full));
    } else if (entry.isFile()) {
      result.push(full);
    }
  }
  return result;
}

function stripTypeScript(code) {
  let js = code;

  // 1. Remove export type { ... } from ...
  js = js.replace(/export\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?/g, '');

  // 2. Remove import type { ... } from ...
  js = js.replace(/import\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?/g, '');

  // 3. Remove interface / type declarations (multi-line)
  js = js.replace(/export\s+(?:interface|type)\s+[A-Za-z0-9_]+(?:<[^>]*>)?\s*(?:=\s*[^;]+;|(?=\{)[^{}]*(?:\{[^{}]*\}[^{}]*)*\})/g, '');
  js = js.replace(/(?:interface|type)\s+[A-Za-z0-9_]+(?:<[^>]*>)?\s*(?:=\s*[^;]+;|(?=\{)[^{}]*(?:\{[^{}]*\}[^{}]*)*\})/g, '');

  // 4. Remove access modifiers (public, private, readonly, protected)
  js = js.replace(/\b(public|private|protected|readonly)\s+/g, '');

  // 5. Remove 'as any', 'as unknown', 'as Type'
  js = js.replace(/\s+as\s+[A-Za-z0-9_<>[\]|&, ]+/g, '');

  // 6. Remove generic type params on functions/classes: foo<T = unknown>( -> foo(
  js = js.replace(/<[A-Za-z0-9_\s=,\{\}\[\]\|\&\?]+>\s*\(/g, '(');

  // 7. Remove return type annotations: ): ReturnType { -> ) {
  // or ): Promise<T> { -> ) {
  js = js.replace(/\):\s*(?:Promise<[^>]+>|[A-Za-z0-9_\[\]|&]+|void|boolean|number|string|any|never|unknown)\s*(?=\{)/g, ') ');
  js = js.replace(/\):\s*(?:Promise<[^>]+>|[A-Za-z0-9_\[\]|&]+|void|boolean|number|string|any|never|unknown)\s*=>/g, ') =>');

  // 8. Remove parameter type annotations: (a: string, b: number = 0) -> (a, b = 0)
  // Clean parameter types inside parens
  js = js.replace(/(\w+)\??\s*:\s*([^,=\)\{]+)(?=[,=\)])/g, (match, p1, p2) => {
    // avoid touching ternary ? :
    if (p2.includes('?')) return match;
    return p1;
  });

  // 9. Remove non-null assertion operator: foo!.bar -> foo.bar, foo![0] -> foo[0]
  js = js.replace(/([a-zA-Z0-9_\)\]])!\./g, '$1.');
  js = js.replace(/([a-zA-Z0-9_\)\]])!\[/g, '$1[');
  js = js.replace(/([a-zA-Z0-9_\)\]])!\(/g, '$1(');
  js = js.replace(/([a-zA-Z0-9_\)\]])!;/g, '$1;');
  js = js.replace(/([a-zA-Z0-9_\)\]])!,/g, '$1,');

  return js;
}

cleanAndBuild();
