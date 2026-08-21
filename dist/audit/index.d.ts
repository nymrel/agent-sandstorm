export * from '../types.js';
import type { AuditEvent, AuditSeverity, AuditIntegrityResult } from '../types.js';

export declare const GENESIS_PREV_HASH: string;
export declare function computeEventHash(
  index: number,
  prevHash: string,
  timestamp: number,
  type: string,
  severity: AuditSeverity,
  payload: Record<string, unknown>
): string;

export declare class AuditLogger {
  constructor(options?: { logFilePath?: string; initialPayload?: Record<string, unknown> });
  recordEvent(type: string, severity?: AuditSeverity, payload?: Record<string, unknown>): AuditEvent;
  verifyIntegrity(): AuditIntegrityResult;
  getEvents(): AuditEvent[];
  getLatestHash(): string;
  exportJson(): string;
}

export declare function exportTimelineAscii(events: AuditEvent[], title?: string): string;
export declare function generateHtmlReport(events: AuditEvent[], integrity: AuditIntegrityResult, metadata?: Record<string, unknown>): string;
export declare function exportHtmlReportToFile(filePath: string, events: AuditEvent[], integrity: AuditIntegrityResult, metadata?: Record<string, unknown>): void;
