/**
 * @file audit.test.js
 * @description Unit tests for Cryptographic SHA-256 Audit Logger & Timeline Generator
 */

import * as assert from 'node:assert';
import { AuditLogger, exportTimelineAscii, generateHtmlReport } from '../dist/audit/index.js';

export async function runAuditTests() {
  console.log('🧪 Running Audit & Cryptographic Verification tests...');

  const logger = new AuditLogger({ initialPayload: { testMode: true } });

  // Test 1: Record chained events
  const ev1 = logger.recordEvent('SNAPSHOT_CREATED', 'info', { snapshotId: 'snap_1', fileCount: 10 });
  const ev2 = logger.recordEvent('EXEC_STARTED', 'info', { command: 'node agent.js' });
  const ev3 = logger.recordEvent('SECRET_BLOCKED', 'critical', { pattern: 'OpenAI API Key', redacted: 'sk-proj-...4A' });
  const ev4 = logger.recordEvent('ROLLBACK_TRIGGERED', 'warn', { snapshotId: 'snap_1', restored: 2 });

  const events = logger.getEvents();
  assert.strictEqual(events.length, 5, 'Should have Genesis + 4 events');
  assert.strictEqual(ev1.prevHash, events[0].hash, 'Event 1 prevHash must point to Genesis hash');
  assert.strictEqual(ev2.prevHash, ev1.hash, 'Event 2 prevHash must point to Event 1 hash');
  assert.strictEqual(ev3.prevHash, ev2.hash, 'Event 3 prevHash must point to Event 2 hash');
  assert.strictEqual(ev4.prevHash, ev3.hash, 'Event 4 prevHash must point to Event 3 hash');
  console.log('  ✓ SHA-256 hash chaining sequence passed');

  // Test 2: Verify Cryptographic Chain Integrity
  const integrity = logger.verifyIntegrity();
  assert.strictEqual(integrity.valid, true, 'Cryptographic chain verification should pass');
  assert.strictEqual(integrity.eventCount, 5, 'Event count should match');
  console.log('  ✓ Tamper-evident integrity verification passed');

  // Test 3: Tamper detection
  const tamperedLogger = new AuditLogger();
  tamperedLogger.recordEvent('STEP_1', 'info', { count: 1 });
  tamperedLogger.recordEvent('STEP_2', 'info', { count: 2 });

  // Malicious attacker tampers with payload of event 1
  tamperedLogger.events[1].payload = { count: 9999 };

  const tamperedIntegrity = tamperedLogger.verifyIntegrity();
  assert.strictEqual(tamperedIntegrity.valid, false, 'Tampered chain must fail verification');
  assert.strictEqual(tamperedIntegrity.corruptedIndex, 1, 'Should identify exact corrupted block index');
  console.log('  ✓ Cryptographic tamper & corruption detection passed');

  // Test 4: ASCII Timeline Generation
  const timeline = exportTimelineAscii(events);
  assert.ok(timeline.includes('SANDSTORM EXECUTION AUDIT TIMELINE'), 'Timeline must include title');
  assert.ok(timeline.includes('[CRIT!]'), 'Timeline must include critical severity badge');
  assert.ok(timeline.includes('SECRET EXFILTRATION BLOCKED'), 'Timeline must format secret block');
  console.log('  ✓ Visual ASCII timeline generation passed');

  // Test 5: HTML Report Dashboard Generation
  const html = generateHtmlReport(events, integrity, {
    workspace: '/test/workspace',
    totalSpendUsd: 0.1234,
    totalTokens: 5000,
    rollbackPerformed: true,
  });
  assert.ok(html.includes('Sandstorm Security Audit'), 'HTML report must include header');
  assert.ok(html.includes('✓ Cryptographically Verified'), 'HTML report must include verified badge');
  assert.ok(html.includes('Parent Organization: JalenBuilds LLC'), 'HTML report must include Dual-Audience parent entity');
  console.log('  ✓ Interactive HTML dashboard generation passed');

  console.log('✅ Audit & Cryptographic tests passed cleanly (5/5)\n');
}
