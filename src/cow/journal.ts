/**
 * @file journal.ts
 * @description Best-effort transaction journal for explicitly tracked filesystem mutations
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { JournalMutation, TransactionJournal, FileSnapshot } from '../types.js';

export class JournalTracker {
  private readonly journalsDir: string;
  private currentTransaction: TransactionJournal | null = null;

  constructor(sandstormDir: string) {
    this.journalsDir = path.join(sandstormDir, 'journals');
    fs.mkdirSync(this.journalsDir, { recursive: true });
  }

  public startTransaction(name: string, baseSnapshotId: string): TransactionJournal {
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

  public recordMutation(mutation: JournalMutation): void {
    if (!this.currentTransaction) {
      return;
    }
    this.currentTransaction.mutations.push(mutation);
    this.persist();
  }

  public getActiveTransaction(): TransactionJournal | null {
    return this.currentTransaction;
  }

  public detectMutations(
    baseFiles: Record<string, FileSnapshot>,
    currentFiles: Record<string, FileSnapshot>
  ): JournalMutation[] {
    const mutations: JournalMutation[] = [];
    const timestamp = Date.now();

    // Check created and modified
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

    // Check deleted
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

  public closeTransaction(): TransactionJournal | null {
    const tx = this.currentTransaction;
    this.currentTransaction = null;
    return tx;
  }

  private persist(): void {
    if (!this.currentTransaction) return;
    const txPath = path.join(this.journalsDir, `${this.currentTransaction.id}.json`);
    fs.writeFileSync(txPath, JSON.stringify(this.currentTransaction, null, 2), 'utf-8');
  }
}
