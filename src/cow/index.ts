/**
 * @file index.ts
 * @description Copy-on-Write Workspace Isolation Engine
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  SnapshotMetadata,
  RollbackResult,
  CommitResult,
  WorkspaceDiff,
  TransactionJournal,
} from '../types.js';
import {
  scanWorkspaceFiles,
  computeTreeHash,
  ObjectStore,
} from './snapshot.js';
import { JournalTracker } from './journal.js';
import { executeRollback, computeWorkspaceDiff } from './rollback.js';

export class CoWSnapshotManager {
  public readonly workspaceRoot: string;
  public readonly sandstormDir: string;
  public readonly snapshotsDir: string;
  public readonly objectStore: ObjectStore;
  public readonly journalTracker: JournalTracker;

  private latestSnapshot: SnapshotMetadata | null = null;

  constructor(workspaceRoot: string, sandstormDir?: string) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.sandstormDir = sandstormDir
      ? path.resolve(sandstormDir)
      : path.join(this.workspaceRoot, '.sandstorm');
    this.snapshotsDir = path.join(this.sandstormDir, 'snapshots');

    fs.mkdirSync(this.snapshotsDir, { recursive: true });
    this.objectStore = new ObjectStore(this.sandstormDir);
    this.journalTracker = new JournalTracker(this.sandstormDir);
  }

  /**
   * Create a content-addressed snapshot of selected workspace files
   */
  public createSnapshot(name?: string, metadata?: Record<string, unknown>): SnapshotMetadata {
    const timestamp = Date.now();
    const id = `snap_${timestamp}_${Math.random().toString(36).substring(2, 8)}`;
    const files = scanWorkspaceFiles(this.workspaceRoot);

    let totalSizeBytes = 0;
    for (const file of Object.values(files)) {
      totalSizeBytes += file.size;
      this.objectStore.putFile(file.path, file.sha256);
    }

    const treeHash = computeTreeHash(files);
    const snapshot: SnapshotMetadata = {
      id,
      name: name || `Snapshot ${new Date(timestamp).toISOString()}`,
      timestamp,
      isoTime: new Date(timestamp).toISOString(),
      workspacePath: this.workspaceRoot,
      fileCount: Object.keys(files).length,
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
  public getSnapshot(id?: string): SnapshotMetadata | null {
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

    if (!/^snap_[a-zA-Z0-9_-]+$/.test(id)) {
      return null;
    }

    const snapshotPath = path.join(this.snapshotsDir, `${id}.json`);
    if (!fs.existsSync(snapshotPath)) {
      return null;
    }

    try {
      return JSON.parse(fs.readFileSync(snapshotPath, 'utf-8')) as SnapshotMetadata;
    } catch {
      return null;
    }
  }

  /**
   * List all stored snapshots
   */
  public listSnapshots(): SnapshotMetadata[] {
    if (!fs.existsSync(this.snapshotsDir)) return [];
    const files = fs.readdirSync(this.snapshotsDir);
    const snapshots: SnapshotMetadata[] = [];

    for (const file of files) {
      if (file.startsWith('snap_') && file.endsWith('.json')) {
        try {
          const content = fs.readFileSync(path.join(this.snapshotsDir, file), 'utf-8');
          snapshots.push(JSON.parse(content) as SnapshotMetadata);
        } catch {
          // ignore corrupted
        }
      }
    }

    return snapshots.sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Start a journal entry for agent writes
   */
  public startTransaction(name = 'agent-session'): TransactionJournal {
    const baseSnapshot = this.getSnapshot() || this.createSnapshot('baseline');
    return this.journalTracker.startTransaction(name, baseSnapshot.id);
  }

  /**
   * Compute diff between current workspace and base snapshot
   */
  public diff(snapshotId?: string): WorkspaceDiff {
    const baseSnapshot = this.getSnapshot(snapshotId);
    if (!baseSnapshot) {
      throw new Error(`Base snapshot not found: ${snapshotId || 'latest'}`);
    }
    return computeWorkspaceDiff(this.workspaceRoot, baseSnapshot);
  }

  /**
   * Request best-effort rollback to a captured snapshot
   */
  public rollback(snapshotId?: string): RollbackResult {
    const baseSnapshot = this.getSnapshot(snapshotId);
    if (!baseSnapshot) {
      return {
        success: false,
        snapshotId: snapshotId || 'unknown',
        restoredFiles: [],
        deletedFiles: [],
        revertedFiles: [],
        durationMs: 0,
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
  public commit(name?: string): CommitResult {
    const startTime = Date.now();
    const activeTx = this.journalTracker.getActiveTransaction();
    const newSnapshot = this.createSnapshot(name || `Committed ${activeTx?.name || 'changes'}`);
    this.journalTracker.closeTransaction();

    return {
      success: true,
      snapshotId: newSnapshot.id,
      transactionId: activeTx?.id,
      fileCount: newSnapshot.fileCount,
      treeHash: newSnapshot.treeHash,
      durationMs: Date.now() - startTime,
    };
  }
}

export * from './snapshot.js';
export * from './journal.js';
export * from './rollback.js';
