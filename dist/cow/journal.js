/**
 * @file journal.ts
 * @description Atomic transaction journal for tracking agent filesystem mutations
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node:fs';
import *'node:path';


export class JournalTracker {
  journalsDir= null;

  constructor(sandstormDir) {
    this.journalsDir = path.join(sandstormDir, 'journals');
    fs.mkdirSync(this.journalsDir, { recursive);
  }

  startTransaction(name, baseSnapshotId) {
    const id = `tx_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    this.currentTransaction = {
      id,
      name,
      startTime),
      baseSnapshotId,
      mutations,
    };
    this.persist();
    return this.currentTransaction;
  }

  recordMutation(mutation) {
    if (!this.currentTransaction) {
      return;
    }
    this.currentTransaction.mutations.push(mutation);
    this.persist();
  }

  getActiveTransaction(): TransactionJournal | null {
    return this.currentTransaction;
  }

  detectMutations(
    baseFiles, FileSnapshot>,
    currentFiles, FileSnapshot>
  ) {
    const mutations= [];
    const timestamp = Date.now();

    // Check created and modified
    for (const [relPath, curFile] of Object.entries(currentFiles)) {
      const baseFile = baseFiles[relPath];
      if (!baseFile) {
        mutations.push({
          type,
          relativePath,
          timestamp,
          currentSha256,
          currentSize,
        });
      } else if (baseFile.sha256 !== curFile.sha256) {
        mutations.push({
          type,
          relativePath,
          timestamp,
          previousSha256,
          currentSha256,
          previousSize,
          currentSize,
        });
      }
    }

    // Check deleted
    for (const [relPath, baseFile] of Object.entries(baseFiles)) {
      if (!currentFiles[relPath]) {
        mutations.push({
          type,
          relativePath,
          timestamp,
          previousSha256,
          previousSize,
        });
      }
    }

    return mutations;
  }

  closeTransaction(): TransactionJournal | null {
    const tx = this.currentTransaction;
    this.currentTransaction = null;
    return tx;
  }

  persist() {
    if (!this.currentTransaction) return;
    const txPath = path.join(this.journalsDir, `${this.currentTransaction.id}.json`);
    fs.writeFileSync(txPath, JSON.stringify(this.currentTransaction, null, 2), 'utf-8');
  }
}
