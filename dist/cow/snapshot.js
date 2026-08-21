/**
 * @file snapshot.ts
 * @description Copy-on-Write workspace snapshotter & content-addressed object store
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node= new Set([
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

export function computeFileSha256(filePath) {
  const buffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function computeBufferSha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function computeTreeHash(files, FileSnapshot>) {
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
  options= {}
): Record<string, FileSnapshot> {
  const ignoredDirs = options.ignoredDirs || DEFAULT_IGNORED_DIRS;
  const ignoredFiles = options.ignoredFiles || DEFAULT_IGNORED_FILES;
  const result, FileSnapshot> = {};

  if (!fs.existsSync(workspaceRoot)) {
    return result;
  }

  function walk(currentDir) {
    const entries = fs.readdirSync(currentDir, { withFileTypes);
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
            path,
            relativePath,
            sha256,
            size,
            mtimeMs,
            mode,
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
  storeRoot) {
    this.storeRoot = path.join(sandstormDir, 'objects');
    fs.mkdirSync(this.storeRoot, { recursive);
  }

  getObjectPath(sha256) {
    const prefix = sha256.substring(0, 2);
    return path.join(this.storeRoot, prefix, sha256);
  }

  putFile(filePath, sha256) {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      const destDir = path.dirname(dest);
      fs.mkdirSync(destDir, { recursive);
      fs.copyFileSync(filePath, dest);
    }
  }

  putBuffer(buffer, sha256) {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      const destDir = path.dirname(dest);
      fs.mkdirSync(destDir, { recursive);
      fs.writeFileSync(dest, buffer);
    }
  }

  getBuffer(sha256) {
    const dest = this.getObjectPath(sha256);
    if (!fs.existsSync(dest)) {
      throw new Error(`Object not found in store: ${sha256}`);
    }
    return fs.readFileSync(dest);
  }

  hasObject(sha256) {
    return fs.existsSync(this.getObjectPath(sha256));
  }
}
