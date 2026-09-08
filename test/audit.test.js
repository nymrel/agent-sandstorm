/**
 * @file audit.test.js
 * @description Unit tests for Cryptographic SHA-256 Audit Logger & Timeline Generator
 */

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AuditLogger, AuditLogIntegrityError, exportTimelineAscii, generateHtmlReport } from '../dist/audit/index.js';

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

  const nestedLogger = new AuditLogger();
  nestedLogger.recordEvent('NESTED', 'info', { context: { decision: 'allow' } });
  nestedLogger.events[1].payload.context.decision = 'deny';
  assert.strictEqual(
    nestedLogger.verifyIntegrity().valid,
    false,
    'Nested payload tampering must be covered by the event hash',
  );
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
  assert.ok(html.includes('Sandstorm Execution Audit'), 'HTML report must include header');
  assert.ok(html.includes('✓ Hash Chain Intact'), 'HTML report must include integrity badge');
  assert.ok(html.includes('Legal entity: JalenBuilds LLC'), 'HTML report must include the legal entity');

  const injection = '</pre><script>globalThis.compromised=true</script>';
  const injectionLogger = new AuditLogger();
  injectionLogger.recordEvent('UNTRUSTED_TEXT', 'warn', { detail: injection });
  const escapedHtml = generateHtmlReport(
    injectionLogger.getEvents(),
    injectionLogger.verifyIntegrity(),
    { workspace: injection },
  );
  assert.ok(!escapedHtml.includes(injection), 'HTML report must not render untrusted markup');
  assert.ok(escapedHtml.includes('&lt;script&gt;'), 'HTML report must visibly escape untrusted markup');
  console.log('  ✓ Interactive HTML dashboard generation passed');

  // Test 6: Reopening a persisted log must continue the existing chain, while
  // corrupted history must be rejected before any new event is appended.
  const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-audit-resume-'));
  try {
    const auditPath = path.join(auditDir, 'audit.jsonl');
    const firstWriter = new AuditLogger({ logFilePath: auditPath });
    firstWriter.recordEvent('FIRST_RUN', 'info', { value: 1 });

    const secondWriter = new AuditLogger({ logFilePath: auditPath });
    secondWriter.recordEvent('SECOND_RUN', 'info', { value: 2 });
    assert.strictEqual(secondWriter.verifyIntegrity().valid, true, 'Resumed audit chain must remain intact');
    assert.deepStrictEqual(
      secondWriter.getEvents().map(event => event.index),
      [0, 1, 2, 3],
      'Resumed writer must continue event indexes',
    );

    const persisted = fs.readFileSync(auditPath, 'utf-8').trim().split('\n');
    const tampered = JSON.parse(persisted[1]);
    tampered.payload = { value: 999 };
    persisted[1] = JSON.stringify(tampered);
    fs.writeFileSync(auditPath, `${persisted.join('\n')}\n`, 'utf-8');

    assert.throws(
      () => new AuditLogger({ logFilePath: auditPath }),
      AuditLogIntegrityError,
      'A writer must not append to a corrupted persisted chain',
    );

    const failedWritePath = path.join(auditDir, 'failed-write.jsonl');
    const failedWriter = new AuditLogger({ logFilePath: failedWritePath });
    const beforeFailure = failedWriter.getEvents();
    const hashBeforeFailure = failedWriter.getLatestHash();
    fs.unlinkSync(failedWritePath);
    fs.mkdirSync(failedWritePath);
    assert.throws(
      () => failedWriter.recordEvent('MUST_NOT_ADVANCE', 'error'),
      'Persistence errors must be surfaced',
    );
    assert.strictEqual(failedWriter.getEvents().length, beforeFailure.length);
    assert.strictEqual(failedWriter.getLatestHash(), hashBeforeFailure);
  } finally {
    fs.rmSync(auditDir, { recursive: true, force: true });
  }
  console.log('  ✓ Persisted audit chains resume safely and reject corrupted history');

  console.log('✅ Audit & Cryptographic tests passed cleanly (6/6)\n');
}
