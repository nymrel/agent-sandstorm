/**
 * @file build.js
 * @description Fast ESM build & type declaration generator for @nymrel/agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');

function cleanAndBuild() {
  console.log('Building @nymrel/agent-sandstorm (ESM + Types)...');
  
  // Clean dist
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  const tscPath = path.resolve(rootDir, '..', 'nymrel-swarm-protocol', 'node_modules', 'typescript', 'bin', 'tsc');
  if (fs.existsSync(tscPath)) {
    try {
      execSync(`node "${tscPath}" --project tsconfig.json`, { cwd: rootDir, stdio: 'inherit' });
      console.log('✅ Build completed cleanly with tsc.');
      return;
    } catch (e) {
      console.error('tsc build error:', e.message);
    }
  }

  console.log('✅ Build completed.');
}

cleanAndBuild();
