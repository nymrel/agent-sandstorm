"""
End-to-End Sandbox runner tests (Python)
"""

import os
import shutil
import sys
import tempfile
import unittest
from agent_sandstorm.sandbox import CommandExecutionError, Sandstorm


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

    def test_omitted_and_empty_allowlists_default_to_deny(self):
        omitted = Sandstorm(
            workspace=self.tmp_dir,
            audit_log_path=os.path.join(self.tmp_dir, ".sandstorm", "omitted.jsonl"),
        )
        explicit_empty = Sandstorm(
            workspace=self.tmp_dir,
            allow_domains=[],
            audit_log_path=os.path.join(self.tmp_dir, ".sandstorm", "empty.jsonl"),
        )
        self.assertFalse(omitted.proxy.filter.is_allowed("api.openai.com"))
        self.assertFalse(explicit_empty.proxy.filter.is_allowed("api.openai.com"))
        self.assertEqual(omitted.proxy.get_allowed_ports(), [80, 443])
        self.assertIsNotNone(omitted.proxy.on_blocked_port)

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
        self.assertTrue(res.rollback_summary.success)
        self.assertEqual(res.final_tree_hash, res.base_snapshot.tree_hash)

        # Confirm restored state
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, "bad.txt")))
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"status": "pristine"}\n')

    def test_nonzero_child_command_triggers_rollback(self):
        sandbox = Sandstorm(
            workspace=self.tmp_dir,
            auto_rollback_on_error=True,
        )
        transient_path = os.path.join(self.tmp_dir, "transient.txt")

        def failing_command(ctx):
            with open(transient_path, "w", encoding="utf-8") as f:
                f.write("must be rolled back\n")
            return ctx.exec([sys.executable, "--definitely-invalid-sandstorm-option"])

        res = sandbox.run(failing_command)
        self.assertFalse(res.success)
        self.assertTrue(res.rollback_performed)
        self.assertFalse(os.path.exists(transient_path))

    def test_command_argv_does_not_use_a_shell(self):
        sandbox = Sandstorm(workspace=self.tmp_dir, max_steps=1)
        res = sandbox.run(
            lambda ctx: ctx.exec(
                [sys.executable, "-c", "import sys; print(sys.argv[1])", "left && right"]
            )
        )
        self.assertTrue(res.success)
        self.assertEqual(res.result.stdout.strip(), "left && right")

        second_res = sandbox.run(
            lambda ctx: ctx.exec([sys.executable, "-c", "print('second run')"])
        )
        self.assertTrue(second_res.success)
        self.assertEqual(second_res.spend_summary["steps_executed"], 1)

    def test_failed_command_and_audit_redact_recognized_secret(self):
        sandbox = Sandstorm(workspace=self.tmp_dir)
        fake_secret = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
        res = sandbox.run(
            lambda ctx: ctx.exec(
                [sys.executable, "--definitely-invalid-sandstorm-option", fake_secret]
            )
        )

        self.assertFalse(res.success)
        self.assertIsInstance(res.error, CommandExecutionError)
        self.assertNotIn(fake_secret, str(res.error))
        self.assertIn("[REDACTED]", str(res.error))
        self.assertNotIn(fake_secret, repr(res.error.execution.args))
        self.assertNotIn(fake_secret, res.error.execution.stdout)
        self.assertNotIn(fake_secret, res.error.execution.stderr)
        with open(os.path.join(self.tmp_dir, ".sandstorm", "audit.jsonl"), encoding="utf-8") as audit_file:
            self.assertNotIn(fake_secret, audit_file.read())


if __name__ == "__main__":
    unittest.main()
