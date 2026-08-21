#!/usr/bin/env node

/**
 * @file sandstorm.js
 * @description CLI launcher for agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const distCliPath = path.join(__dirname, '..', 'dist', 'cli', 'index.js');
  const srcCliPath = path.join(__dirname, '..', 'src', 'cli', 'index.js');

  let targetPath = distCliPath;
  if (!fs.existsSync(distCliPath) && fs.existsSync(srcCliPath)) {
    targetPath = srcCliPath;
  }

  try {
    const { runCli } = await import(pathToFileURL(targetPath).href);
    const exitCode = await runCli(process.argv.slice(2));
    process.exit(exitCode);
  } catch (err) {
    console.error('Sandstorm CLI Error:', err);
    process.exit(1);
  }
}

main();
