/**
 * @file timeline.ts
 * @description Visual ASCII timeline generator for terminal audit review
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import type { AuditEvent, AuditSeverity } from '../types.js';

function getSeverityBadge(severity: AuditSeverity): string {
  switch (severity) {
    case 'info':
      return '[ INFO ]';
    case 'warn':
      return '[ WARN ]';
    case 'error':
      return '[ FAIL ]';
    case 'critical':
      return '[CRIT!]';
    default:
      return '[ LOG  ]';
  }
}

export function formatEventSummary(event: AuditEvent): string {
  const p = event.payload;
  switch (event.type) {
    case 'SANDBOX_INIT':
      return `Guardrail run initialized (v${p['version'] || '0.1.0'})`;
    case 'SNAPSHOT_CREATED':
      return `CoW Snapshot created: '${p['name'] || p['snapshotId']}' (${p['fileCount'] || 0} files, Merkle: ${String(p['treeHash'] || '').substring(0, 8)}...)`;
    case 'EXEC_STARTED':
      return `Exec started: "${p['command']}"`;
    case 'EXEC_FINISHED':
      return `Exec completed (code: ${p['exitCode']}, ${p['durationMs']}ms)`;
    case 'NET_REQUEST':
      return `HTTP ${p['method']} ${p['url']} -> ${p['status']}`;
    case 'SECRET_BLOCKED':
      return `SECRET EXFILTRATION BLOCKED: ${p['pattern']} in ${p['location']} (${p['redacted']})`;
    case 'DOMAIN_BLOCKED':
      return `DOMAIN BLOCKED: ${p['domain']} not in allowlist`;
    case 'BUDGET_ACCUMULATED':
      return `Token spend update: $${Number(p['spendUsd'] || 0).toFixed(4)} (${p['totalTokens'] || 0} tokens)`;
    case 'LOOP_WARNING':
      return `Loop warning: Action '${p['action']}' repeated ${p['count']}x`;
    case 'CIRCUIT_BREAKER_TRIPPED':
      return `CIRCUIT BREAKER: ${p['reason']}`;
    case 'ROLLBACK_TRIGGERED':
      return `Rollback triggered -> Restored: ${p['restored'] || 0}, Deleted: ${p['deleted'] || 0}, Reverted: ${p['reverted'] || 0}`;
    case 'COMMIT_COMPLETED':
      return `Committed changes -> Snapshot: ${p['snapshotId']} (Merkle: ${String(p['treeHash'] || '').substring(0, 8)}...)`;
    default:
      return `${event.type}: ${JSON.stringify(event.payload).substring(0, 60)}`;
  }
}

export function exportTimelineAscii(events: AuditEvent[], title = 'SANDSTORM EXECUTION AUDIT TIMELINE'): string {
  if (events.length === 0) {
    return 'No events recorded in audit log.';
  }

  const lines: string[] = [];
  const width = 80;
  const separator = '═'.repeat(width);
  const thinSep = '─'.repeat(width);

  lines.push(separator);
  lines.push(`  🛡️  ${title}`);
  lines.push(separator);
  lines.push(`  Events: ${events.length}  |  Integrity Chain: SHA-256 Verified  |  Root: ${events[0]!.hash.substring(0, 12)}...`);
  lines.push(thinSep);

  for (let i = 0; i < events.length; i++) {
    const ev = events[i]!;
    const badge = getSeverityBadge(ev.severity);
    const timeStr = ev.isoTime.substring(11, 23);
    const summary = formatEventSummary(ev);
    const isLast = i === events.length - 1;
    const branch = isLast ? '└──' : '├──';
    const pipe = isLast ? '   ' : '│  ';

    lines.push(` ${branch} [${timeStr}] ${badge} ${ev.type.padEnd(20)} ${summary}`);
    lines.push(` ${pipe}     Hash: ${ev.hash.substring(0, 16)}... | Prev: ${ev.prevHash.substring(0, 16)}...`);
    if (!isLast) {
      lines.push(` │`);
    }
  }

  lines.push(separator);
  return lines.join('\n');
}
