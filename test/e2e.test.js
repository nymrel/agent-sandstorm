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

    // Verify pristine state restoration
    assert.strictEqual(fs.existsSync(badFile), false, 'Bad file written during failing run must be deleted');
    assert.strictEqual(fs.existsSync(featurePath), true, 'Deleted feature file must be restored');
    assert.strictEqual(
      fs.readFileSync(configPath, 'utf-8'),
      JSON.stringify({ database: 'production_crm', active: true }, null, 2),
      'Corrupted configuration file must be reverted to pristine baseline'
    );
    console.log('  ✓ Automatic CoW Rollback on agent exception & damage prevention passed');

    console.log('✅ Sandstorm End-to-End tests passed cleanly (2/2)\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
