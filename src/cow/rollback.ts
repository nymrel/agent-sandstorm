/**
 * @file rollback.ts
 * @description Best-effort rollback for captured regular workspace files
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SnapshotMetadata, RollbackResult, WorkspaceDiff } from '../types.js';
import { scanWorkspaceFiles, ObjectStore } from './snapshot.js';

function assertSafeRestoreTarget(workspaceRoot: string, targetPath: string): void {
  const resolvedRoot = path.resolve(workspaceRoot);
  const resolvedTarget = path.resolve(targetPath);
  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
    throw new Error(`Refusing unsafe rollback target outside the workspace: ${targetPath}`);
  }

  let current = resolvedRoot;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) {
        throw new Error(`Refusing rollback through symbolic link: ${path.relative(resolvedRoot, current)}`);
      }
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}

export function computeWorkspaceDiff(
  workspaceRoot: string,
  baseSnapshot: SnapshotMetadata
): WorkspaceDiff {
  const currentFiles = scanWorkspaceFiles(workspaceRoot);
  const baseFiles = baseSnapshot.files;

  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  let unchangedCount = 0;

  for (const [relPath, curFile] of Object.entries(currentFiles)) {
    const baseFile = baseFiles[relPath];
    if (!baseFile) {
      added.push(relPath);
    } else if (baseFile.sha256 !== curFile.sha256) {
      modified.push(relPath);
    } else {
      unchangedCount++;
    }
  }

  for (const relPath of Object.keys(baseFiles)) {
    if (!currentFiles[relPath]) {
      deleted.push(relPath);
    }
  }

  return {
    baseSnapshotId: baseSnapshot.id,
    added,
    modified,
    deleted,
    unchangedCount,
    totalChanged: added.length + modified.length + deleted.length,
  };
}

export function executeRollback(
  workspaceRoot: string,
  baseSnapshot: SnapshotMetadata,
  objectStore: ObjectStore
): RollbackResult {
  const startTime = Date.now();
  const restoredFiles: string[] = [];
  const deletedFiles: string[] = [];
  const revertedFiles: string[] = [];

  try {
    const currentFiles = scanWorkspaceFiles(workspaceRoot);
    const baseFiles = baseSnapshot.files;

    // 1. Delete files that were created after the snapshot
    for (const [relPath, curFile] of Object.entries(currentFiles)) {
      if (!baseFiles[relPath]) {
        try {
          if (fs.existsSync(curFile.path)) {
            fs.unlinkSync(curFile.path);
            deletedFiles.push(relPath);
          }
        } catch (err: unknown) {
          throw new Error(`Failed to delete added file ${relPath}: ${String(err)}`);
        }
      }
    }

    // 2. Revert modified files & restore deleted files
    for (const [relPath, baseFile] of Object.entries(baseFiles)) {
      const curFile = currentFiles[relPath];
      const targetPath = path.join(workspaceRoot, relPath);

      if (!curFile) {
        // File was deleted; restore it
        assertSafeRestoreTarget(workspaceRoot, targetPath);
        const targetDir = path.dirname(targetPath);
        fs.mkdirSync(targetDir, { recursive: true });
        const content = objectStore.getBuffer(baseFile.sha256);
        fs.writeFileSync(targetPath, content, { mode: baseFile.mode });
        restoredFiles.push(relPath);
      } else if (curFile.sha256 !== baseFile.sha256) {
        // File was modified; revert it
        assertSafeRestoreTarget(workspaceRoot, targetPath);
        const content = objectStore.getBuffer(baseFile.sha256);
        fs.writeFileSync(targetPath, content, { mode: baseFile.mode });
        revertedFiles.push(relPath);
      }
    }

    // 3. Remove any empty directories created by agent
    cleanupEmptyDirectories(workspaceRoot);

    const durationMs = Date.now() - startTime;
    return {
      success: true,
      snapshotId: baseSnapshot.id,
      restoredFiles,
      deletedFiles,
      revertedFiles,
      durationMs,
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;
    return {
      success: false,
      snapshotId: baseSnapshot.id,
      restoredFiles,
      deletedFiles,
      revertedFiles,
      durationMs,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function cleanupEmptyDirectories(dir: string, isRoot = true): boolean {
  if (!fs.existsSync(dir)) return true;

  let isEmpty = true;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '.sandstorm' || entry.name === '.git') {
        isEmpty = false;
        continue;
      }
      const subDirEmpty = cleanupEmptyDirectories(fullPath, false);
      if (subDirEmpty) {
        try {
          fs.rmdirSync(fullPath);
        } catch {
          isEmpty = false;
        }
      } else {
        isEmpty = false;
      }
    } else {
      isEmpty = false;
    }
  }

  return !isRoot && isEmpty;
}
