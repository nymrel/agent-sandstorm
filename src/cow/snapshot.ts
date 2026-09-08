/**
 * @file snapshot.ts
 * @description Copy-on-Write workspace snapshotter & content-addressed object store
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { FileSnapshot } from '../types.js';

const DEFAULT_IGNORED_DIRS = new Set([
  '.git',
  '.sandstorm',
  'node_modules',
  'dist',
  'build',
  '.venv',
  'venv',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.cache',
  '.next',
  '.nuxt',
  'coverage',
]);

const DEFAULT_IGNORED_FILES = new Set([
  '.DS_Store',
  'Thumbs.db',
]);

export function computeFileSha256(filePath: string): string {
  const buffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function computeBufferSha256(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function computeTreeHash(files: Record<string, FileSnapshot>): string {
  const sortedPaths = Object.keys(files).sort();
  const hasher = crypto.createHash('sha256');
  for (const relPath of sortedPaths) {
    const file = files[relPath];
    if (file) {
      hasher.update(`${relPath}:${file.sha256}:${file.size}\n`);
    }
  }
  return hasher.digest('hex');
}

export interface ScanOptions {
  ignoredDirs?: Set<string>;
  ignoredFiles?: Set<string>;
  customIgnorePatterns?: RegExp[];
}

export function scanWorkspaceFiles(
  workspaceRoot: string,
  options: ScanOptions = {}
): Record<string, FileSnapshot> {
  const ignoredDirs = options.ignoredDirs || DEFAULT_IGNORED_DIRS;
  const ignoredFiles = options.ignoredFiles || DEFAULT_IGNORED_FILES;
  const result: Record<string, FileSnapshot> = {};

  if (!fs.existsSync(workspaceRoot)) {
    return result;
  }

  function walk(currentDir: string): void {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(workspaceRoot, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (ignoredDirs.has(entry.name) || options.customIgnorePatterns?.some(p => p.test(entry.name))) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        if (ignoredFiles.has(entry.name) || options.customIgnorePatterns?.some(p => p.test(entry.name))) {
          continue;
        }
        try {
          const stats = fs.statSync(fullPath);
          const sha256 = computeFileSha256(fullPath);
          result[relativePath] = {
            path: fullPath,
            relativePath,
            sha256,
            size: stats.size,
            mtimeMs: stats.mtimeMs,
            mode: stats.mode,
          };
        } catch {
          // File might have been locked or deleted during scan
        }
      }
    }
  }

  walk(workspaceRoot);
  return result;
}

export class ObjectStore {
  private readonly storeRoot: string;

  constructor(sandstormDir: string) {
    this.storeRoot = path.join(sandstormDir, 'objects');
    fs.mkdirSync(this.storeRoot, { recursive: true });
  }

  public getObjectPath(sha256: string): string {
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw new TypeError('Object identifiers must be lowercase SHA-256 digests');
    }
    const prefix = sha256.substring(0, 2);
    return path.join(this.storeRoot, prefix, sha256);
  }

  public putFile(filePath: string, sha256: string): void {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      const destDir = path.dirname(dest);
      fs.mkdirSync(destDir, { recursive: true });
      fs.copyFileSync(filePath, dest);
    }
  }

  public putBuffer(buffer: Buffer, sha256: string): void {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      const destDir = path.dirname(dest);
      fs.mkdirSync(destDir, { recursive: true });
      fs.writeFileSync(dest, buffer);
    }
  }

  public getBuffer(sha256: string): Buffer {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      throw new Error(`Object not found in store: ${sha256}`);
    }
    const buffer = fs.readFileSync(dest);
    if (computeBufferSha256(buffer) !== sha256) {
      throw new Error(`Object failed SHA-256 verification: ${sha256}`);
    }
    return buffer;
  }

  public hasObject(sha256: string): boolean {
    return fs.existsSync(this.getObjectPath(sha256));
  }
}
