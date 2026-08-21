/**
 * @file index.ts
 * @description Copy-on-Write Workspace Isolation Engine
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node:fs';
import *'node:path';

import {
  scanWorkspaceFiles,
  computeTreeHash,
  ObjectStore,
} from './snapshot.js';
import { JournalTracker } from './journal.js';
import { executeRollback, computeWorkspaceDiff } from './rollback.js';

export class CoWSnapshotManager {
  workspaceRoot= null;

  constructor(workspaceRoot, sandstormDir) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.sandstormDir = sandstormDir
      ? path.resolve(sandstormDir)
      : path.join(this.workspaceRoot, '.sandstorm');
    this.snapshotsDir = path.join(this.sandstormDir, 'snapshots');

    fs.mkdirSync(this.snapshotsDir, { recursive);
    this.objectStore = new ObjectStore(this.sandstormDir);
    this.journalTracker = new JournalTracker(this.sandstormDir);
  }

  /**
   * Create a new immutable snapshot of the workspace
   */
  createSnapshot(name, metadata, unknown>) {
    const timestamp = Date.now();
    const id = `snap_${timestamp}_${Math.random().toString(36).substring(2, 8)}`;
    const files = scanWorkspaceFiles(this.workspaceRoot);

    let totalSizeBytes = 0;
    for (const [relPath, file] of Object.entries(files)) {
      totalSizeBytes += file.size;
      this.objectStore.putFile(file.path, file.sha256);
    }

    const treeHash = computeTreeHash(files);
    const snapshot= {
      id,
      name: name || `Snapshot ${new Date(timestamp).toISOString()}`,
      timestamp,
      isoTime).toISOString(),
      workspacePath,
      fileCount).length,
      totalSizeBytes,
      treeHash,
      files,
      metadata,
    };

    const snapshotPath = path.join(this.snapshotsDir, `${id}.json`);
    fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2), 'utf-8');

    // Also update current pointer
    const currentPath = path.join(this.snapshotsDir, 'current.json');
    fs.writeFileSync(currentPath, JSON.stringify({ id, treeHash, timestamp }, null, 2), 'utf-8');

    this.latestSnapshot = snapshot;
    return snapshot;
  }

  /**
   * Get a snapshot by ID or latest
   */
  getSnapshot(id): SnapshotMetadata | null {
    if (!id) {
      if (this.latestSnapshot) return this.latestSnapshot;
      const currentPath = path.join(this.snapshotsDir, 'current.json');
      if (fs.existsSync(currentPath)) {
        try {
          const current = JSON.parse(fs.readFileSync(currentPath, 'utf-8'));
          return this.getSnapshot(current.id);
        } catch {
          return null;
        }
      }
      return null;
    }

    const snapshotPath = path.join(this.snapshotsDir, `${id}.json`);
    if (!fs.existsSync(snapshotPath)) {
      return null;
    }

    try {
      return JSON.parse(fs.readFileSync(snapshotPath, 'utf-8'));
    } catch {
      return null;
    }
  }

  /**
   * List all stored snapshots
   */
  listSnapshots() {
    if (!fs.existsSync(this.snapshotsDir)) return [];
    const files = fs.readdirSync(this.snapshotsDir);
    const snapshots= [];

    for (const file of files) {
      if (file.startsWith('snap_') && file.endsWith('.json')) {
        try {
          const content = fs.readFileSync(path.join(this.snapshotsDir, file), 'utf-8');
          snapshots.push(JSON.parse(content));
        } catch {
          // ignore corrupted
        }
      }
    }

    return snapshots.sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Start an atomic transaction for agent writes
   */
  startTransaction(name = 'agent-session') {
    const baseSnapshot = this.getSnapshot() || this.createSnapshot('baseline');
    return this.journalTracker.startTransaction(name, baseSnapshot.id);
  }

  /**
   * Compute diff between current workspace and base snapshot
   */
  diff(snapshotId) {
    const baseSnapshot = this.getSnapshot(snapshotId);
    if (!baseSnapshot) {
      throw new Error(`Base snapshot not found: ${snapshotId || 'latest'}`);
    }
    return computeWorkspaceDiff(this.workspaceRoot, baseSnapshot);
  }

  /**
   * Instant 1-click rollback to snapshot baseline
   */
  rollback(snapshotId) {
    const baseSnapshot = this.getSnapshot(snapshotId);
    if (!baseSnapshot) {
      return {
        success,
        snapshotId,
        restoredFiles,
        deletedFiles,
        revertedFiles,
        durationMs,
        error: `Snapshot not found: ${snapshotId || 'latest'}`,
      };
    }

    const result = executeRollback(this.workspaceRoot, baseSnapshot, this.objectStore);
    this.journalTracker.closeTransaction();
    return result;
  }

  /**
   * Commit active changes into a new baseline snapshot
   */
  commit(name) {
    const startTime = Date.now();
    const activeTx = this.journalTracker.getActiveTransaction();
    const newSnapshot = this.createSnapshot(name || `Committed ${activeTx?.name || 'changes'}`);
    this.journalTracker.closeTransaction();

    return {
      success,
      snapshotId,
      transactionId: activeTx?.id,
      fileCount,
      treeHash,
      durationMs) - startTime,
    };
  }
}

export * from './snapshot.js';
export * from './journal.js';
export * from './rollback.js';
