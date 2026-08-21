/**
 * @file logger.ts
 * @description Cryptographic SHA-256 tamper-evident audit logger
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { AuditEvent, AuditSeverity, AuditIntegrityResult } from '../types.js';

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export function computeEventHash(
  index: number,
  prevHash: string,
  timestamp: number,
  type: string,
  severity: AuditSeverity,
  payload: Record<string, unknown>
): string {
  // Sort payload keys deterministically for reproducible hashing
  const sortedPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const serialized = `${index}|${prevHash}|${timestamp}|${type}|${severity}|${sortedPayload}`;
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

export class AuditLogger {
  private events: AuditEvent[] = [];
  private readonly logFilePath?: string;
  private latestHash = GENESIS_PREV_HASH;

  constructor(options: { logFilePath?: string; initialPayload?: Record<string, unknown> } = {}) {
    this.logFilePath = options.logFilePath;
    if (this.logFilePath) {
      const dir = path.dirname(this.logFilePath);
      fs.mkdirSync(dir, { recursive: true });
    }

    // Initialize Genesis Event
    this.recordEvent('SANDBOX_INIT', 'info', {
      version: '1.0.0',
      engine: 'agent-sandstorm',
      timestamp: Date.now(),
      ...options.initialPayload,
    });
  }

  /**
   * Record a new audit event into the cryptographic hash chain
   */
  public recordEvent(
    type: string,
    severity: AuditSeverity,
    payload: Record<string, unknown> = {}
  ): AuditEvent {
    const index = this.events.length;
    const timestamp = Date.now();
    const isoTime = new Date(timestamp).toISOString();
    const prevHash = this.latestHash;

    const hash = computeEventHash(index, prevHash, timestamp, type, severity, payload);

    const event: AuditEvent = {
      index,
      prevHash,
      hash,
      timestamp,
      isoTime,
      type,
      severity,
      payload,
    };

    this.events.push(event);
    this.latestHash = hash;

    if (this.logFilePath) {
      try {
        fs.appendFileSync(this.logFilePath, JSON.stringify(event) + '\n', 'utf-8');
      } catch {
        // If append fails, keep in-memory
      }
    }

    return event;
  }

  /**
   * Cryptographically verify the integrity of the audit event chain
   */
  public verifyIntegrity(): AuditIntegrityResult {
    if (this.events.length === 0) {
      return {
        valid: true,
        eventCount: 0,
        genesisHash: GENESIS_PREV_HASH,
        latestHash: GENESIS_PREV_HASH,
      };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i]!;

      // 1. Verify index sequence
      if (event.index !== i) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

      // 2. Verify previous hash pointer
      if (event.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

      // 3. Verify event SHA-256 hash
      const computedHash = computeEventHash(
        event.index,
        event.prevHash,
        event.timestamp,
        event.type,
        event.severity,
        event.payload
      );

      if (computedHash !== event.hash) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

      expectedPrevHash = event.hash;
    }

    return {
      valid: true,
      eventCount: this.events.length,
      genesisHash: this.events[0]!.hash,
      latestHash: this.latestHash,
    };
  }

  public getEvents(): AuditEvent[] {
    return [...this.events];
  }

  public getLatestHash(): string {
    return this.latestHash;
  }

  public exportJson(): string {
    return JSON.stringify(this.events, null, 2);
  }
}
