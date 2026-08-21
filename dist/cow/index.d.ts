/**
 * @file index.ts
 * @description Copy-on-Write Workspace Isolation Engine
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
import type { SnapshotMetadata, RollbackResult, CommitResult, WorkspaceDiff, TransactionJournal } from '../types.js';
import { ObjectStore } from './snapshot.js';
import { JournalTracker } from './journal.js';
export declare class CoWSnapshotManager {
    readonly workspaceRoot: string;
    readonly sandstormDir: string;
    readonly snapshotsDir: string;
    readonly objectStore: ObjectStore;
    readonly journalTracker: JournalTracker;
    private latestSnapshot;
    constructor(workspaceRoot: string, sandstormDir?: string);
    /**
     * Create a new immutable snapshot of the workspace
     */
    createSnapshot(name?: string, metadata?: Record<string, unknown>): SnapshotMetadata;
    /**
     * Get a snapshot by ID or latest
     */
    getSnapshot(id?: string): SnapshotMetadata | null;
    /**
     * List all stored snapshots
     */
    listSnapshots(): SnapshotMetadata[];
    /**
     * Start an atomic transaction for agent writes
     */
    startTransaction(name?: string): TransactionJournal;
    /**
     * Compute diff between current workspace and base snapshot
     */
    diff(snapshotId?: string): WorkspaceDiff;
    /**
     * Instant 1-click rollback to snapshot baseline
     */
    rollback(snapshotId?: string): RollbackResult;
    /**
     * Commit active changes into a new baseline snapshot
     */
    commit(name?: string): CommitResult;
}
export * from './snapshot.js';
export * from './journal.js';
export * from './rollback.js';
//# sourceMappingURL=index.d.ts.map