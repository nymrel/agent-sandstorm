/**
 * @file build-contract.test.js
 * @description Fail-closed build contract tests for scripts/build.js
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 *
 * Each test drives the real build script against a throwaway project created
 * in a temporary directory (stub TypeScript compiler included). Fixtures only
 * ever read/write inside their own temporary directory.
 *
 * Run: node --test test/build-contract.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BUILD_SCRIPT_SOURCE = path.join(__dirname, '..', 'scripts', 'build.js');
const STAGING_DIR_NAME = '.dist-staging';
const SUCCESS_MARKER = '✅';
const FRESH_OUTPUT_MARKER = '// fresh build output';

// The copied build script uses an explicit .mjs suffix so this contract remains
// valid on Node 18, where ESM syntax is not auto-detected outside a package.
// Stub compilers keep their extensionless CommonJS form and receive the same
// argv shape as real tsc.

/** Exits 0 and emits one fresh output file into the requested --outDir. */
const TSC_OK = `
const fs = require('node:fs');
const path = require('node:path');
const outIndex = process.argv.indexOf('--outDir');
if (outIndex === -1 || !process.argv[outIndex + 1]) {
  process.stderr.write('stub tsc: missing --outDir\\n');
  process.exit(2);
}
fs.mkdirSync(process.argv[outIndex + 1], { recursive: true });
fs.writeFileSync(
  path.join(process.argv[outIndex + 1], 'index.js'),
  ${JSON.stringify(FRESH_OUTPUT_MARKER)} + '\\n',
);
`;

/** Exits nonzero like a real tsc type-error run. */
const TSC_TYPE_ERROR = `
process.stderr.write('error TS9999: simulated TypeScript failure\\n');
process.exit(2);
`;

/** Exits 0 but produces nothing; the build must treat this as a failure. */
const TSC_SILENT_NO_OUTPUT = `
process.stdout.write('stub tsc: exited 0 without compiling anything\\n');
`;

function createTempProject(t, { tscStub } = {}) {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-build-contract-'));
  t.after(() => fs.rmSync(projectDir, { recursive: true, force: true }));

  fs.writeFileSync(
    path.join(projectDir, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          outDir: './dist',
          rootDir: './src',
        },
        include: ['src/**/*'],
      },
      null,
      2,
    ),
  );

  fs.mkdirSync(path.join(projectDir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(projectDir, 'src', 'index.ts'), 'export const ready: boolean = true;\n');
  fs.mkdirSync(path.join(projectDir, 'scripts'), { recursive: true });
  fs.copyFileSync(BUILD_SCRIPT_SOURCE, path.join(projectDir, 'scripts', 'build.mjs'));

  if (tscStub) {
    const binDir = path.join(projectDir, 'node_modules', 'typescript', 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(path.join(binDir, 'tsc'), tscStub);
  }

  return projectDir;
}

function plantStaleDist(projectDir) {
  const distDir = path.join(projectDir, 'dist');
  fs.mkdirSync(distDir, { recursive: true });
  fs.writeFileSync(path.join(distDir, 'index.js'), '// STALE OUTPUT FROM A PREVIOUS BUILD\n');
  return distDir;
}

/**
 * Preload that makes the final staging->dist rename fail deterministically
 * (simulated EXDEV). Written inside the temp project; loaded via a --require
 * argument prepended to the child command (spawnSync has no execArgv option).
 */
const SWAP_FAILURE_PRELOAD = `
const fs = require('node:fs');
const originalRenameSync = fs.renameSync;
fs.renameSync = function patchedRenameSync(source, destination) {
  const base = String(destination).split(/[\\\\/]/).pop();
  if (base === 'dist') {
    const error = new Error('simulated rename failure: EXDEV cross-device link not permitted');
    error.code = 'EXDEV';
    throw error;
  }
  return originalRenameSync.call(fs, source, destination);
};
`;

function runBuild(projectDir, { requirePreload } = {}) {
  const preloadArgs = requirePreload ? ['--require', requirePreload] : [];
  return spawnSync(process.execPath, [...preloadArgs, path.join(projectDir, 'scripts', 'build.mjs')], {
    encoding: 'utf8',
    shell: false,
  });
}

function combinedOutput(run) {
  return `${run.stdout ?? ''}${run.stderr ?? ''}`;
}

test('successful build swaps fresh output into dist and leaves no staging dir', (t) => {
  const projectDir = createTempProject(t, { tscStub: TSC_OK });
  const staleDist = plantStaleDist(projectDir);

  const run = runBuild(projectDir);

  assert.equal(run.status, 0, `expected exit 0, got ${run.status}\n${combinedOutput(run)}`);
  assert.ok(run.stdout.includes(SUCCESS_MARKER), 'a successful build must report success');

  const distIndex = fs.readFileSync(path.join(staleDist, 'index.js'), 'utf8');
  assert.ok(distIndex.includes(FRESH_OUTPUT_MARKER), 'dist must contain freshly generated output');
  assert.ok(!distIndex.includes('STALE OUTPUT'), 'stale dist content must be replaced');

  assert.equal(fs.existsSync(path.join(projectDir, STAGING_DIR_NAME)), false, 'staging dir must be swapped away');
});

test('TypeScript failure exits nonzero, never prints success, and removes stale dist', (t) => {
  const projectDir = createTempProject(t, { tscStub: TSC_TYPE_ERROR });
  plantStaleDist(projectDir);

  const run = runBuild(projectDir);

  assert.equal(run.status, 2, 'build must propagate the compiler exit code');
  const output = combinedOutput(run);
  assert.ok(!output.includes(SUCCESS_MARKER), 'must never print success after failure');
  assert.equal(fs.existsSync(path.join(projectDir, 'dist')), false, 'stale dist must not survive a failed build');
  assert.equal(fs.existsSync(path.join(projectDir, STAGING_DIR_NAME)), false, 'partial staging output must be cleaned');
});

test('missing TypeScript compiler fails closed with a clear error', (t) => {
  const projectDir = createTempProject(t); // no stub -> no repo-local compiler
  plantStaleDist(projectDir);

  // Precondition: the studio fallback cannot resolve from inside the temp tree.
  const studioFallback = path.resolve(
    projectDir, '..', 'nymrel-swarm-protocol', 'node_modules', 'typescript', 'bin', 'tsc',
  );
  assert.equal(fs.existsSync(studioFallback), false, 'test precondition: no studio fallback under temp parent');

  const run = runBuild(projectDir);

  assert.equal(run.status, 1, 'missing compiler must exit with a clear nonzero code');
  const output = combinedOutput(run);
  assert.ok(output.includes('TypeScript compiler not found'), 'must explain the missing compiler');
  assert.ok(!output.includes(SUCCESS_MARKER), 'must never print success after failure');
  assert.equal(fs.existsSync(path.join(projectDir, 'dist')), false, 'fail-closed must remove consumable dist');
});

test('compiler that exits 0 without producing output is treated as a failure', (t) => {
  const projectDir = createTempProject(t, { tscStub: TSC_SILENT_NO_OUTPUT });
  plantStaleDist(projectDir);

  const run = runBuild(projectDir);

  assert.notEqual(run.status, 0, 'silent no-output success must fail closed');
  const output = combinedOutput(run);
  assert.ok(!output.includes(SUCCESS_MARKER), 'must never print success after failure');
  assert.equal(fs.existsSync(path.join(projectDir, 'dist')), false, 'no misleading dist may remain');
});

test('failed staging-to-dist swap cleans staging and dist before exiting nonzero', (t) => {
  const projectDir = createTempProject(t, { tscStub: TSC_OK });
  plantStaleDist(projectDir);

  const preloadPath = path.join(projectDir, 'swap-failure-preload.cjs');
  fs.writeFileSync(preloadPath, SWAP_FAILURE_PRELOAD);

  const run = runBuild(projectDir, { requirePreload: preloadPath });

  assert.equal(run.status, 1, 'a failed swap must exit nonzero');
  const output = combinedOutput(run);
  assert.ok(!output.includes(SUCCESS_MARKER), 'must never print success after a failed swap');
  assert.ok(
    output.includes('could not move compiled output into dist'),
    'must explain that the swap failed',
  );
  assert.equal(
    fs.existsSync(path.join(projectDir, STAGING_DIR_NAME)),
    false,
    'staging tree must not survive a failed swap',
  );
  assert.equal(
    fs.existsSync(path.join(projectDir, 'dist')),
    false,
    'stale/partial dist must be cleaned after a failed swap',
  );
});
