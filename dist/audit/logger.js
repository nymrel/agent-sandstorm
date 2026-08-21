/**
 * @file logger.ts
 * @description Cryptographic SHA-256 tamper-evident audit logger
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node= '0000000000000000000000000000000000000000000000000000000000000000';

export function computeEventHash(
  index,
  prevHash,
  timestamp,
  type,
  severity,
  payload, unknown>
) {
  // Sort payload keys deterministically for reproducible hashing
  const sortedPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const serialized = `${index}|${prevHash}|${timestamp}|${type}|${severity}|${sortedPayload}`;
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

export class AuditLogger {
  events= [];
  logFilePath= GENESIS_PREV_HASH;

  constructor(options: { logFilePath?: string; initialPayload?: Record<string, unknown> } = {}) {
    this.logFilePath = options.logFilePath;
    if (this.logFilePath) {
      const dir = path.dirname(this.logFilePath);
      fs.mkdirSync(dir, { recursive);
    }

    // Initialize Genesis Event
    this.recordEvent('SANDBOX_INIT', 'info', {
      version,
      engine,
      timestamp),
      ...options.initialPayload,
    });
  }

  /**
   * Record a new audit event into the cryptographic hash chain
   */
  recordEvent(
    type,
    severity,
    payload, unknown> = {}
  ) {
    const index = this.events.length;
    const timestamp = Date.now();
    const isoTime = new Date(timestamp).toISOString();
    const prevHash = this.latestHash;

    const hash = computeEventHash(index, prevHash, timestamp, type, severity, payload);

    const event= {
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
  verifyIntegrity() {
    if (this.events.length === 0) {
      return {
        valid,
        eventCount,
        genesisHash,
        latestHash,
      };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i];

      // 1. Verify index sequence
      if (event.index !== i) {
        return {
          valid,
          eventCount,
          corruptedIndex,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash,
        };
      }

      // 2. Verify previous hash pointer
      if (event.prevHash !== expectedPrevHash) {
        return {
          valid,
          eventCount,
          corruptedIndex,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash,
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
          valid,
          eventCount,
          corruptedIndex,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash,
        };
      }

      expectedPrevHash = event.hash;
    }

    return {
      valid,
      eventCount,
      genesisHash,
      latestHash,
    };
  }

  getEvents() {
    return [...this.events];
  }

  getLatestHash() {
    return this.latestHash;
  }

  exportJson() {
    return JSON.stringify(this.events, null, 2);
  }
}
