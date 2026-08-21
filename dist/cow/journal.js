/**
 * @file journal.js
 * @description Atomic transaction journal for tracking agent filesystem mutations
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export class JournalTracker {
  constructor(sandstormDir) {
    this.journalsDir = path.join(sandstormDir, 'journals');
    fs.mkdirSync(this.journalsDir, { recursive: true });
    this.currentTransaction = null;
  }

  startTransaction(name, baseSnapshotId) {
    const id = `tx_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    this.currentTransaction = {
      id,
      name,
      startTime: Date.now(),
      baseSnapshotId,
      mutations: [],
    };
    this.persist();
    return this.currentTransaction;
  }

  recordMutation(mutation) {
    if (!this.currentTransaction) return;
    this.currentTransaction.mutations.push(mutation);
    this.persist();
  }

  getActiveTransaction() {
    return this.currentTransaction;
  }

  detectMutations(baseFiles, currentFiles) {
    const mutations = [];
    const timestamp = Date.now();

    for (const [relPath, curFile] of Object.entries(currentFiles)) {
      const baseFile = baseFiles[relPath];
      if (!baseFile) {
        mutations.push({
          type: 'created',
          relativePath: relPath,
          timestamp,
          currentSha256: curFile.sha256,
          currentSize: curFile.size,
        });
      } else if (baseFile.sha256 !== curFile.sha256) {
        mutations.push({
          type: 'modified',
          relativePath: relPath,
          timestamp,
          previousSha256: baseFile.sha256,
          currentSha256: curFile.sha256,
          previousSize: baseFile.size,
          currentSize: curFile.size,
        });
      }
    }

    for (const [relPath, baseFile] of Object.entries(baseFiles)) {
      if (!currentFiles[relPath]) {
        mutations.push({
          type: 'deleted',
          relativePath: relPath,
          timestamp,
          previousSha256: baseFile.sha256,
          previousSize: baseFile.size,
        });
      }
    }

    return mutations;
  }

  closeTransaction() {
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
