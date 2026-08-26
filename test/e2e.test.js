/**
 * @file e2e.test.js
 * @description End-to-end sandbox runner and automatic rollback tests
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as assert from 'node:assert';
import { Sandstorm } from '../dist/index.js';

export async function runE2eTests() {
  console.log('🧪 Running Sandstorm End-to-End Sandbox tests...');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-e2e-test-'));

  try {
    // 1. Setup initial workspace files
    const configPath = path.join(tmpDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify({ database: 'production_crm', active: true }, null, 2), 'utf-8');

    const sandbox = new Sandstorm({
      workspace: tmpDir,
      allowDomains: ['api.openai.com', 'registry.npmjs.org'],
      maxSpendUsd: 2.00,
      maxSteps: 10,
      autoRollbackOnError: true,
      silent: true,
    });
    const defaultDenySandbox = new Sandstorm({
      workspace: tmpDir,
      auditLogPath: path.join(tmpDir, '.sandstorm', 'default-deny-audit.jsonl'),
    });
    assert.deepStrictEqual(defaultDenySandbox.options.allowDomains, [], 'Omitted allowlist must default to deny');

    // Test 1: Successful agent session with token recording & file creation
    const res1 = await sandbox.run(async (ctx) => {
      ctx.recordTokenUsage('gpt-4o', 1000, 200);
      ctx.recordStep('agent_reasoning', 'Planning architecture');
      const newFile = path.join(ctx.workspace, 'feature.ts');
      fs.writeFileSync(newFile, 'export const active = true;\n', 'utf-8');
      return { status: 'completed' };
    });

    assert.strictEqual(res1.success, true, 'Execution should succeed');
    assert.strictEqual(res1.rollbackPerformed, false, 'Rollback should not be triggered on success');
    assert.strictEqual(res1.auditSummary.verified, true, 'Audit log must be cryptographically verified');
    assert.strictEqual(fs.existsSync(path.join(tmpDir, 'feature.ts')), true, 'Created file should exist');
    console.log('  ✓ Autonomous execution session with token tracking passed');

    const shellFree = await sandbox.run(async (ctx) => {
      return ctx.exec('node -e "process.stdout.write(process.argv[1])" "left && right"');
    });
    assert.strictEqual(shellFree.success, true, 'Shell-free quoted command should succeed');
    assert.strictEqual(shellFree.result?.stdout, 'left && right', 'Shell metacharacters must remain plain argv text');
    assert.strictEqual(shellFree.spendSummary.stepsExecuted, 1, 'Each run must receive a fresh step budget');
    console.log('  ✓ Default command execution preserves arguments without a shell');

    // Test 2: Failing/Corrupting agent session with AUTOMATIC 1-CLICK ROLLBACK
    const featurePath = path.join(tmpDir, 'feature.ts');
    const badFile = path.join(tmpDir, 'malware.sh');

    const res2 = await sandbox.run(async (ctx) => {
      // Rogue agent corrupts config and writes malicious script
      fs.writeFileSync(configPath, 'CORRUPTED DATABASE CONFIG', 'utf-8');
      fs.writeFileSync(badFile, 'rm -rf /', 'utf-8');
      fs.unlinkSync(featurePath);

      // Rogue agent crashes or raises unhandled error / loops
      throw new Error('Agent execution crashed due to unhandled API exception');
    });

    assert.strictEqual(res2.success, false, 'Execution must report failure');
    assert.strictEqual(res2.rollbackPerformed, true, 'Automatic CoW rollback must be performed on error');
    assert.ok(res2.rollbackSummary, 'Rollback summary must be provided');
    assert.strictEqual(res2.rollbackSummary.success, true, 'Rollback summary must report completion');
    assert.strictEqual(res2.finalTreeHash, res2.baseSnapshot.treeHash, 'Final hash must be measured after rollback');

    // Verify pristine state restoration
    assert.strictEqual(fs.existsSync(badFile), false, 'Bad file written during failing run must be deleted');
    assert.strictEqual(fs.existsSync(featurePath), true, 'Deleted feature file must be restored');
    assert.strictEqual(
      fs.readFileSync(configPath, 'utf-8'),
      JSON.stringify({ database: 'production_crm', active: true }, null, 2),
      'Corrupted configuration file must be reverted to pristine baseline'
    );
    console.log('  ✓ Automatic CoW Rollback on agent exception & damage prevention passed');

    // Test 3: A nonzero child command is a sandbox failure by default. This is
    // the CLI safety contract: command failures must trigger rollback and a
    // nonzero Sandstorm result instead of being presented as success.
    const commandFailureArtifact = path.join(tmpDir, 'before-command-failure.txt');
    const res3 = await sandbox.run(async (ctx) => {
      fs.writeFileSync(commandFailureArtifact, 'must be rolled back\n', 'utf-8');
      return ctx.exec('node --definitely-invalid-sandstorm-option');
    });

    assert.strictEqual(res3.success, false, 'A nonzero child command must fail the sandbox run');
    assert.strictEqual(res3.rollbackPerformed, true, 'A nonzero child command must trigger rollback');
    assert.strictEqual(
      fs.existsSync(commandFailureArtifact),
      false,
      'Files created before a failed child command must be removed by rollback',
    );
    console.log('  ✓ Nonzero child command fails closed and triggers rollback');

    const fakeSecret = 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz';
    const secretResult = await sandbox.run(async (ctx) => {
      return ctx.exec(`node --definitely-invalid-sandstorm-option ${fakeSecret}`);
    });
    const serializedSecretResult = JSON.stringify(secretResult);
    assert.ok(!serializedSecretResult.includes(fakeSecret), 'Failed-command results must redact recognized secrets');
    assert.ok(serializedSecretResult.includes('[REDACTED]'), 'Redacted failure result should make sanitization visible');
    const auditLog = fs.readFileSync(path.join(tmpDir, '.sandstorm', 'audit.jsonl'), 'utf-8');
    assert.ok(!auditLog.includes(fakeSecret), 'Audit log must not retain recognized command-line secrets');
    assert.ok(!secretResult.error?.execution?.stdout?.includes(fakeSecret), 'Failed-command stdout must be redacted');
    assert.ok(!secretResult.error?.execution?.stderr?.includes(fakeSecret), 'Failed-command stderr must be redacted');
    console.log('  ✓ Failed command and audit output redact recognized credentials');

    console.log('✅ Sandstorm End-to-End tests passed cleanly (5/5)\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
