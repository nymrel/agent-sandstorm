/**
 * @file cli.test.js
 * @description CLI regression tests for argv preservation and fail-closed limits
 */

import * as assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export async function runCliTests() {
  console.log('🧪 Running CLI contract tests...');
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-cli-test-'));

  try {
    const argumentProbe = 'process.stdout.write(JSON.stringify(process.argv.slice(1)))';
    const preserved = spawnSync(
      process.execPath,
      [
        'bin/sandstorm.js',
        'run',
        '--json',
        '--workspace',
        workspace,
        '--',
        process.execPath,
        '-e',
        argumentProbe,
        'left && right',
        '--workspace',
        'child-value',
      ],
      { cwd: process.cwd(), encoding: 'utf8', shell: false },
    );

    assert.strictEqual(preserved.status, 0, preserved.stderr || preserved.stdout);
    const preservedResult = JSON.parse(preserved.stdout);
    assert.strictEqual(preservedResult.success, true, 'CLI child command should succeed');
    assert.deepStrictEqual(
      JSON.parse(preservedResult.result.stdout),
      ['left && right', '--workspace', 'child-value'],
      'Arguments after -- must reach the child unchanged',
    );
    console.log('  ✓ Arguments after -- are preserved without shell interpretation');

    const zeroStepLimit = spawnSync(
      process.execPath,
      [
        'bin/sandstorm.js',
        'run',
        '--json',
        '--workspace',
        workspace,
        '--max-steps',
        '0',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      { cwd: process.cwd(), encoding: 'utf8', shell: false },
    );
    assert.strictEqual(zeroStepLimit.status, 1, 'A zero step ceiling must not be treated as an omitted limit');
    const limitResult = JSON.parse(zeroStepLimit.stdout);
    assert.strictEqual(limitResult.success, false);
    assert.strictEqual(limitResult.rollbackPerformed, true);
    console.log('  ✓ Zero-valued CLI limits remain active and fail closed');

    console.log('✅ CLI contract tests passed cleanly (2/2)\n');
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}
