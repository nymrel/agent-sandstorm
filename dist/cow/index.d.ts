export * from '../types.js';
export * from './snapshot.js';
export * from './journal.js';
export * from './rollback.js';

import type { SnapshotMetadata, RollbackResult, CommitResult, WorkspaceDiff, TransactionJournal } from '../types.js';
import { ObjectStore } from './snapshot.js';
import { JournalTracker } from './journal.js';

export declare class CoWSnapshotManager {
  readonly workspaceRoot: string;
  readonly sandstormDir: string;
  readonly snapshotsDir: string;
  readonly objectStore: ObjectStore;
  readonly journalTracker: JournalTracker;
  constructor(workspaceRoot: string, sandstormDir?: string);
  createSnapshot(name?: string, metadata?: Record<string, unknown>): SnapshotMetadata;
  getSnapshot(id?: string): SnapshotMetadata | null;
  listSnapshots(): SnapshotMetadata[];
  startTransaction(name?: string): TransactionJournal;
  diff(snapshotId?: string): WorkspaceDiff;
  rollback(snapshotId?: string): RollbackResult;
  commit(name?: string): CommitResult;
}
