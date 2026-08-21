/**
 * @file logger.js
 * @description Cryptographic SHA-256 tamper-evident audit logger
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export function computeEventHash(index, prevHash, timestamp, type, severity, payload) {
  const sortedPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const serialized = `${index}|${prevHash}|${timestamp}|${type}|${severity}|${sortedPayload}`;
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

export class AuditLogger {
  constructor(options = {}) {
    this.logFilePath = options.logFilePath;
    this.events = [];
    this.latestHash = GENESIS_PREV_HASH;

    if (this.logFilePath) {
      const dir = path.dirname(this.logFilePath);
      fs.mkdirSync(dir, { recursive: true });
    }

    this.recordEvent('SANDBOX_INIT', 'info', {
      version: '1.0.0',
      engine: 'agent-sandstorm',
      timestamp: Date.now(),
      ...options.initialPayload,
    });
  }

  recordEvent(type, severity = 'info', payload = {}) {
    const index = this.events.length;
    const timestamp = Date.now();
    const isoTime = new Date(timestamp).toISOString();
    const prevHash = this.latestHash;

    const hash = computeEventHash(index, prevHash, timestamp, type, severity, payload);

    const event = {
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
        // keep in-memory
      }
    }

    return event;
  }

  verifyIntegrity() {
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
      const event = this.events[i];

      if (event.index !== i) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

      if (event.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

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
      genesisHash: this.events[0].hash,
      latestHash: this.latestHash,
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
