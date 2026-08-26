/**
 * @file cow.test.js
 * @description Unit tests for Copy-on-Write Workspace Isolation Engine
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as assert from 'node:assert';
import { CoWSnapshotManager } from '../dist/cow/index.js';

export async function runCowTests() {
  console.log('🧪 Running CoW Engine tests...');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-cow-test-'));
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandstorm-cow-outside-'));

  try {
    // 1. Setup workspace with initial files
    const file1 = path.join(tmpDir, 'src', 'app.js');
    const file2 = path.join(tmpDir, 'README.md');
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(file1, 'console.log("hello world");\n', 'utf-8');
    fs.writeFileSync(file2, '# Sandstorm Test\n', 'utf-8');

    const cow = new CoWSnapshotManager(tmpDir);

    // Test 1: Snapshot creation
    const snapshot1 = cow.createSnapshot('initial');
    assert.strictEqual(snapshot1.fileCount, 2, 'Initial snapshot should contain 2 files');
    assert.ok(snapshot1.treeHash, 'Snapshot should have non-empty Merkle tree hash');
    assert.ok(snapshot1.id.startsWith('snap_'), 'Snapshot ID format valid');
    assert.strictEqual(cow.getSnapshot('../../outside'), null, 'Snapshot IDs must not permit path traversal');
    console.log('  ✓ Snapshot creation & Merkle tree calculation passed');

    // Test 2: File mutations & diff
    const file3 = path.join(tmpDir, 'src', 'new-feature.js');
    fs.writeFileSync(file3, 'export const secret = 42;\n', 'utf-8');
    fs.writeFileSync(file1, 'console.log("MODIFIED CODE");\n', 'utf-8');
    fs.unlinkSync(file2); // delete README.md

    const diff = cow.diff(snapshot1.id);
    assert.strictEqual(diff.added.length, 1, 'Should detect 1 added file');
    assert.strictEqual(diff.modified.length, 1, 'Should detect 1 modified file');
    assert.strictEqual(diff.deleted.length, 1, 'Should detect 1 deleted file');
    assert.strictEqual(diff.added[0], 'src/new-feature.js');
    assert.strictEqual(diff.modified[0], 'src/app.js');
    assert.strictEqual(diff.deleted[0], 'README.md');
    console.log('  ✓ Mutation detection & workspace diff passed');

    // Test 3: Instant 1-click Rollback
    const rollbackRes = cow.rollback(snapshot1.id);
    assert.strictEqual(rollbackRes.success, true, 'Rollback should succeed');
    assert.strictEqual(rollbackRes.deletedFiles.length, 1, 'Should delete newly added file');
    assert.strictEqual(rollbackRes.revertedFiles.length, 1, 'Should revert modified file');
    assert.strictEqual(rollbackRes.restoredFiles.length, 1, 'Should restore deleted file');

    // Verify workspace filesystem state matches baseline
    assert.strictEqual(fs.existsSync(file3), false, 'New file must be deleted after rollback');
    assert.strictEqual(fs.existsSync(file2), true, 'Deleted file must be restored after rollback');
    assert.strictEqual(fs.readFileSync(file1, 'utf-8'), 'console.log("hello world");\n', 'Modified file content must be reverted');
    assert.strictEqual(fs.readFileSync(file2, 'utf-8'), '# Sandstorm Test\n', 'Restored file content must match original');

    const postRollbackDiff = cow.diff(snapshot1.id);
    assert.strictEqual(postRollbackDiff.totalChanged, 0, 'Post-rollback diff must be 0 changes');

    const protectedDir = path.join(tmpDir, 'protected');
    const protectedFile = path.join(protectedDir, 'value.txt');
    const outsideFile = path.join(outsideDir, 'value.txt');
    fs.mkdirSync(protectedDir);
    fs.writeFileSync(protectedFile, 'captured\n');
    fs.writeFileSync(outsideFile, 'outside\n');
    const symlinkSnapshot = cow.createSnapshot('before-symlink-swap');
    fs.rmSync(protectedDir, { recursive: true });
    fs.symlinkSync(outsideDir, protectedDir, 'dir');
    const symlinkRollback = cow.rollback(symlinkSnapshot.id);
    assert.strictEqual(symlinkRollback.success, false, 'Rollback must refuse a symlinked parent path');
    assert.strictEqual(fs.readFileSync(outsideFile, 'utf8'), 'outside\n', 'Rollback must not write outside the workspace');

    fs.unlinkSync(protectedDir);
    fs.mkdirSync(protectedDir);
    fs.writeFileSync(protectedFile, 'object-original\n');
    const objectSnapshot = cow.createSnapshot('before-object-corruption');
    const captured = objectSnapshot.files['protected/value.txt'];
    fs.writeFileSync(cow.objectStore.getObjectPath(captured.sha256), 'corrupted-object\n');
    fs.writeFileSync(protectedFile, 'workspace-modified\n');
    const corruptRollback = cow.rollback(objectSnapshot.id);
    assert.strictEqual(corruptRollback.success, false, 'Rollback must reject a corrupted stored object');
    assert.strictEqual(fs.readFileSync(protectedFile, 'utf8'), 'workspace-modified\n');
    console.log('  ✓ Best-effort rollback of captured regular files passed');

    // Test 4: Commit transaction
    fs.writeFileSync(file1, 'console.log("COMMITTED");\n', 'utf-8');
    const commitRes = cow.commit('feature-approved');
    assert.strictEqual(commitRes.success, true, 'Commit should succeed');
    assert.ok(commitRes.snapshotId, 'Commit should return new snapshot ID');

    const postCommitDiff = cow.diff(commitRes.snapshotId);
    assert.strictEqual(postCommitDiff.totalChanged, 0, 'Post-commit diff against new snapshot must be 0');
    console.log('  ✓ Commit & baseline promotion passed');

    console.log('✅ CoW Engine tests passed cleanly (4/4)\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(outsideDir, { recursive: true, force: true });
  }
}
