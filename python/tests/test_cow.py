"""
Unit tests for CoW Workspace Isolation Engine (Python)
"""

import os
import shutil
import tempfile
import unittest
from agent_sandstorm.cow import CoWSnapshotManager


class TestCoW(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sandstorm-py-cow-")
        self.file1 = os.path.join(self.tmp_dir, "app.py")
        self.file2 = os.path.join(self.tmp_dir, "config.json")

        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("print('hello world')\n")
        with open(self.file2, "w", encoding="utf-8") as f:
            f.write('{"env": "prod"}\n')

        self.cow = CoWSnapshotManager(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_snapshot_and_diff(self):
        snap = self.cow.create_snapshot("initial")
        self.assertEqual(snap.file_count, 2)
        self.assertTrue(bool(snap.tree_hash))

        # Mutate
        file3 = os.path.join(self.tmp_dir, "extra.py")
        with open(file3, "w", encoding="utf-8") as f:
            f.write("x = 1\n")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("print('MODIFIED')\n")
        os.remove(self.file2)

        diff = self.cow.diff(snap.id)
        self.assertEqual(len(diff.added), 1)
        self.assertEqual(len(diff.modified), 1)
        self.assertEqual(len(diff.deleted), 1)

    def test_rollback(self):
        snap = self.cow.create_snapshot("base")

        # Create malicious file & modify
        bad_file = os.path.join(self.tmp_dir, "malware.py")
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("import os; os.system('bad')\n")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("print('MUTATED')\n")
        os.remove(self.file2)

        res = self.cow.rollback(snap.id)
        self.assertTrue(res.success)
        self.assertEqual(len(res.deleted_files), 1)
        self.assertEqual(len(res.reverted_files), 1)
        self.assertEqual(len(res.restored_files), 1)

        self.assertFalse(os.path.exists(bad_file))
        self.assertTrue(os.path.exists(self.file2))
        with open(self.file1, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "print('hello world')\n")


if __name__ == "__main__":
    unittest.main()
