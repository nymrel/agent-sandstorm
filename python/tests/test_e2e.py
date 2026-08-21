"""
End-to-End Sandbox runner tests (Python)
"""

import os
import shutil
import tempfile
import unittest
from agent_sandstorm.sandbox import Sandstorm


class TestE2E(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sandstorm-py-e2e-")
        self.config_path = os.path.join(self.tmp_dir, "settings.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write('{"status": "pristine"}\n')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_e2e_successful_run(self):
        sandbox = Sandstorm(
            workspace=self.tmp_dir,
            allow_domains=["api.openai.com"],
            max_spend_usd=1.00,
        )

        def agent_action(ctx):
            ctx.record_tokens("gpt-4o", 1000, 100)
            new_file = os.path.join(ctx.workspace, "output.txt")
            with open(new_file, "w", encoding="utf-8") as f:
                f.write("result\n")
            return "ok"

        res = sandbox.run(agent_action)
        self.assertTrue(res.success)
        self.assertFalse(res.rollback_performed)
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "output.txt")))

    def test_e2e_error_with_auto_rollback(self):
        sandbox = Sandstorm(
            workspace=self.tmp_dir,
            auto_rollback_on_error=True,
        )

        def rogue_agent(ctx):
            with open(self.config_path, "w", encoding="utf-8") as f:
                f.write('{"status": "CORRUPTED"}\n')
            bad_file = os.path.join(ctx.workspace, "bad.txt")
            with open(bad_file, "w", encoding="utf-8") as f:
                f.write("destroy\n")
            raise RuntimeError("Agent crashed during execution")

        res = sandbox.run(rogue_agent)
        self.assertFalse(res.success)
        self.assertTrue(res.rollback_performed)

        # Confirm restored state
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, "bad.txt")))
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"status": "pristine"}\n')


if __name__ == "__main__":
    unittest.main()
