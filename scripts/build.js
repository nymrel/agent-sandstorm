/**
 * @file build.js
 * @description Fail-closed ESM build & type declaration generator for @nymrel/agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 *
 * Contract:
 * - TypeScript is resolved deterministically from this repository's dependency
 *   tree. No compiler => clear nonzero failure.
 * - Compilation runs through an argv-based child process (no shell string).
 * - Any failure (missing compiler, spawn error, TypeScript errors, empty output)
 *   exits nonzero, never prints a success message, and leaves no `dist` behind
 *   that downstream consumers could mistake for fresh output.
 * - Success swaps a fully compiled staging directory into `dist`.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const STAGING_DIR_NAME = '.dist-staging';

/**
 * Staging path of the in-flight build, tracked so the outermost exception
 * handler can still clean it up if an unexpected error escapes runBuild's
 * guarded sections. `.dist-staging` must never survive any exit path.
 */
let ACTIVE_STAGING_DIR = null;

/** Best-effort removal of the active staging tree (outer exception path). */
function cleanupActiveStagingDir() {
  if (!ACTIVE_STAGING_DIR) {
    return;
  }
  try {
    fs.rmSync(ACTIVE_STAGING_DIR, { recursive: true, force: true });
  } catch {
    // Best effort only; the primary failure is reported by the caller.
  } finally {
    ACTIVE_STAGING_DIR = null;
  }
}

/** Deterministic compiler candidate list; first existing entry wins. */
function compilerCandidates(rootDir) {
  return [
    // Self-contained clean checkouts must never depend on a sibling studio repo.
    path.join(rootDir, 'node_modules', 'typescript', 'bin', 'tsc'),
    path.join(rootDir, 'node_modules', 'typescript', 'lib', 'tsc.js'),
  ];
}

function resolveCompiler(rootDir) {
  for (const candidate of compilerCandidates(rootDir)) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function removeDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function removeDirForFailure(dir) {
  try {
    removeDir(dir);
    return null;
  } catch (error) {
    return `could not remove ${dir}: ${error?.message ?? error}`;
  }
}

function countFiles(dir) {
  let count = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      count += countFiles(path.join(dir, entry.name));
    } else if (entry.isFile()) {
      count += 1;
    }
  }
  return count;
}

/** Fail closed: report, destroy any consumable dist output, exit nonzero. */
function failClosed({ rootDir, stagingDir, reason, exitCode = 1 }) {
  console.error(`❌ Build failed: ${reason}`);
  const cleanupErrors = [
    removeDirForFailure(stagingDir),
    removeDirForFailure(path.join(rootDir, 'dist')),
  ].filter(Boolean);
  if (cleanupErrors.length === 0) {
    console.error('   Removed dist/ so stale or partial output cannot be consumed as fresh.');
  } else {
    for (const cleanupError of cleanupErrors) {
      console.error(`   Cleanup failure: ${cleanupError}`);
    }
  }
  process.exit(exitCode);
}

function runBuild(rootDir) {
  console.log('Building @nymrel/agent-sandstorm (ESM + Types)...');

  const distDir = path.join(rootDir, 'dist');
  const stagingDir = path.join(rootDir, STAGING_DIR_NAME);
  ACTIVE_STAGING_DIR = stagingDir;

  const tscPath = resolveCompiler(rootDir);
  if (!tscPath) {
    console.error('❌ Build failed: TypeScript compiler not found.');
    console.error('   Checked:');
    for (const candidate of compilerCandidates(rootDir)) {
      console.error(`     - ${candidate}`);
    }
    console.error('   Install a repo-local compiler with: npm install --save-dev typescript');
    failClosed({ rootDir, stagingDir, reason: 'no usable TypeScript compiler' });
  }

  // Compile into a staging directory so a failure can never leave a partial
  // dist/ that looks like a successful build.
  try {
    removeDir(stagingDir);
  } catch (error) {
    failClosed({ rootDir, stagingDir, reason: `could not clean staging output (${error?.message ?? error})` });
  }

  const result = spawnSync(
    process.execPath,
    [tscPath, '--project', 'tsconfig.json', '--outDir', stagingDir],
    { cwd: rootDir, stdio: 'inherit', shell: false },
  );

  if (result.error) {
    failClosed({ rootDir, stagingDir, reason: `could not launch TypeScript compiler (${result.error.message})` });
  }

  if (result.status !== 0) {
    const how = result.status === null ? `killed by signal ${result.signal}` : `exit code ${result.status}`;
    failClosed({
      rootDir,
      stagingDir,
      reason: `TypeScript reported errors (${how})`,
      exitCode: result.status ?? 1,
    });
  }

  let producedFiles = 0;
  try {
    producedFiles = fs.existsSync(stagingDir) ? countFiles(stagingDir) : 0;
  } catch (error) {
    failClosed({ rootDir, stagingDir, reason: `could not inspect compiler output (${error?.message ?? error})` });
  }

  if (producedFiles === 0) {
    failClosed({ rootDir, stagingDir, reason: 'compiler exited successfully but produced no output' });
  }

  // Success only: swap the fully compiled staging output into place. If the
  // swap itself fails, destroy both the staging tree and any stale/partial
  // dist before exiting nonzero — never leave `.dist-staging` behind.
  try {
    removeDir(distDir);
    fs.renameSync(stagingDir, distDir);
  } catch (error) {
    failClosed({
      rootDir,
      stagingDir,
      reason: `could not move compiled output into dist (${error?.message ?? error})`,
    });
  }

  ACTIVE_STAGING_DIR = null;
  console.log('✅ Build completed cleanly with tsc.');
}

try {
  runBuild(rootDir);
} catch (error) {
  console.error(`❌ Build failed: ${error?.message ?? error}`);
  cleanupActiveStagingDir();
  process.exit(1);
}
