/**
 * @file rollback.js
 * @description Instant 1-click atomic rollback engine for pristine workspace restoration
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { scanWorkspaceFiles } from './snapshot.js';

export function computeWorkspaceDiff(workspaceRoot, baseSnapshot) {
  const currentFiles = scanWorkspaceFiles(workspaceRoot);
  const baseFiles = baseSnapshot.files;

  const added = [];
  const modified = [];
  const deleted = [];
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

export function executeRollback(workspaceRoot, baseSnapshot, objectStore) {
  const startTime = Date.now();
  const restoredFiles = [];
  const deletedFiles = [];
  const revertedFiles = [];

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
        } catch (err) {
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
        const targetDir = path.dirname(targetPath);
        fs.mkdirSync(targetDir, { recursive: true });
        const content = objectStore.getBuffer(baseFile.sha256);
        fs.writeFileSync(targetPath, content, { mode: baseFile.mode });
        restoredFiles.push(relPath);
      } else if (curFile.sha256 !== baseFile.sha256) {
        // File was modified; revert it
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
  } catch (err) {
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

function cleanupEmptyDirectories(dir, isRoot = true) {
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
