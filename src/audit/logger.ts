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
const AUDIT_SEVERITIES: AuditSeverity[] = ['info', 'warn', 'error', 'critical'];

export class AuditLogIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditLogIntegrityError';
  }
}

function canonicalizeJson(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Audit payload numbers must be finite');
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeJson(item) ?? null);
  }

  if (typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Audit payload values must be JSON objects, arrays, or primitives');
    }

    const canonical: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = canonicalizeJson((value as Record<string, unknown>)[key]);
      if (item !== undefined) canonical[key] = item;
    }
    return canonical;
  }

  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    return undefined;
  }

  throw new TypeError(`Audit payload contains unsupported value type: ${typeof value}`);
}

function serializePayload(payload: Record<string, unknown>): string {
  return JSON.stringify(canonicalizeJson(payload));
}

function isValidEventShape(event: AuditEvent): boolean {
  if (!Number.isInteger(event.index) || event.index < 0) return false;
  if (!/^[a-f0-9]{64}$/.test(event.prevHash) || !/^[a-f0-9]{64}$/.test(event.hash)) return false;
  if (!Number.isFinite(event.timestamp) || Number.isNaN(new Date(event.timestamp).getTime())) return false;
  if (typeof event.isoTime !== 'string' || typeof event.type !== 'string' || !event.type.trim()) return false;
  if (!AUDIT_SEVERITIES.includes(event.severity)) return false;
  if (!event.payload || typeof event.payload !== 'object' || Array.isArray(event.payload)) return false;

  try {
    serializePayload(event.payload);
  } catch {
    return false;
  }
  return true;
}

export function computeEventHash(
  index: number,
  prevHash: string,
  timestamp: number,
  type: string,
  severity: AuditSeverity,
  payload: Record<string, unknown>
): string {
  // Canonicalize recursively so nested payload values are covered by the hash.
  const sortedPayload = serializePayload(payload);
  const serialized = `${index}|${prevHash}|${timestamp}|${type}|${severity}|${sortedPayload}`;
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

export class AuditLogger {
  private events: AuditEvent[] = [];
  private readonly logFilePath?: string;
  private latestHash = GENESIS_PREV_HASH;

  constructor(options: { logFilePath?: string; initialPayload?: Record<string, unknown> } = {}) {
    this.logFilePath = options.logFilePath;
    let resumed = false;
    if (this.logFilePath) {
      const dir = path.dirname(this.logFilePath);
      fs.mkdirSync(dir, { recursive: true });
      if (fs.existsSync(this.logFilePath) && fs.statSync(this.logFilePath).size > 0) {
        this.loadPersistedEvents(this.logFilePath);
        const integrity = this.verifyIntegrity();
        if (!integrity.valid) {
          throw new AuditLogIntegrityError(
            `Refusing to append to an invalid audit chain at event ${integrity.corruptedIndex ?? 'unknown'}`,
          );
        }
        resumed = true;
      }
    }

    this.recordEvent(resumed ? 'SANDBOX_RESUME' : 'SANDBOX_INIT', 'info', {
      version: '0.1.0',
      engine: 'agent-sandstorm',
      timestamp: Date.now(),
      ...options.initialPayload,
    });
  }

  private loadPersistedEvents(logFilePath: string): void {
    const lines = fs.readFileSync(logFilePath, 'utf-8').split(/\r?\n/).filter(line => line.trim());
    this.events = lines.map((line, lineIndex) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (error) {
        throw new AuditLogIntegrityError(
          `Audit log line ${lineIndex + 1} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      if (
        !parsed ||
        typeof parsed !== 'object' ||
        !isValidEventShape(parsed as AuditEvent)
      ) {
        throw new AuditLogIntegrityError(`Audit log line ${lineIndex + 1} has an invalid event shape`);
      }
      return parsed as AuditEvent;
    });
    this.latestHash = this.events.at(-1)?.hash ?? GENESIS_PREV_HASH;
  }

  /**
   * Record a new audit event into the cryptographic hash chain
   */
  public recordEvent(
    type: string,
    severity: AuditSeverity,
    payload: Record<string, unknown> = {}
  ): AuditEvent {
    if (typeof type !== 'string' || !type.trim()) throw new TypeError('Audit event type must not be empty');
    if (!AUDIT_SEVERITIES.includes(severity)) throw new TypeError(`Invalid audit severity: ${String(severity)}`);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new TypeError('Audit event payload must be an object');
    }

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

    if (this.logFilePath) {
      fs.appendFileSync(this.logFilePath, JSON.stringify(event) + '\n', 'utf-8');
    }

    // Do not advance in-memory state unless persistence succeeded.
    this.events.push(event);
    this.latestHash = hash;

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

      if (!isValidEventShape(event) || event.isoTime !== new Date(event.timestamp).toISOString()) {
        return {
          valid: false,
          eventCount: this.events.length,
          corruptedIndex: i,
          genesisHash: this.events[0]?.hash || GENESIS_PREV_HASH,
          latestHash: this.latestHash,
        };
      }

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
