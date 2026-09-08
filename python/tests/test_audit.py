"""
Unit tests for Cryptographic Audit Logger (Python)
"""

import json
import os
import tempfile
import unittest

from agent_sandstorm.audit import (
    AuditLogger,
    AuditLogIntegrityError,
    export_timeline_ascii,
    generate_html_report,
)


class TestAudit(unittest.TestCase):
    def test_audit_hash_chain(self):
        logger = AuditLogger()
        logger.record_event("SNAPSHOT_CREATED", "info", {"count": 5})
        logger.record_event("EXEC_STARTED", "info", {"cmd": "pytest"})
        logger.record_event("SECRET_BLOCKED", "critical", {"pattern": "OpenAI"})

        integrity = logger.verify_integrity()
        self.assertTrue(integrity["valid"])
        self.assertEqual(integrity["event_count"], 4)

        # Tamper with payload
        logger.events[1].payload = {"hacked": True}
        tampered_integrity = logger.verify_integrity()
        self.assertFalse(tampered_integrity["valid"])
        self.assertEqual(tampered_integrity["corrupted_index"], 1)

        nested_logger = AuditLogger()
        nested_logger.record_event("NESTED", "info", {"context": {"decision": "allow"}})
        nested_logger.events[1].payload["context"]["decision"] = "deny"
        self.assertFalse(nested_logger.verify_integrity()["valid"])

    def test_timeline_and_html(self):
        logger = AuditLogger()
        logger.record_event("TEST_EVENT", "info", {"data": 123})
        timeline = export_timeline_ascii(logger.events)
        self.assertIn("SANDSTORM", timeline)

        html = generate_html_report(logger.events, logger.verify_integrity(), "/workspace")
        self.assertIn("Sandstorm Audit Report", html)

        injection = "</pre><script>globalThis.compromised=true</script>"
        logger.record_event("UNTRUSTED_TEXT", "warn", {"detail": injection})
        escaped_html = generate_html_report(logger.events, logger.verify_integrity(), injection)
        self.assertNotIn(injection, escaped_html)
        self.assertIn("&lt;script&gt;", escaped_html)

    def test_persisted_chain_resumes_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory(prefix="sandstorm-audit-resume-") as audit_dir:
            audit_path = os.path.join(audit_dir, "audit.jsonl")
            first_writer = AuditLogger(log_file_path=audit_path)
            first_writer.record_event("FIRST_RUN", "info", {"value": 1})

            second_writer = AuditLogger(log_file_path=audit_path)
            second_writer.record_event("SECOND_RUN", "info", {"value": 2})
            self.assertTrue(second_writer.verify_integrity()["valid"])
            self.assertEqual([event.index for event in second_writer.events], [0, 1, 2, 3])

            with open(audit_path, encoding="utf-8") as audit_file:
                lines = audit_file.read().splitlines()
            tampered = json.loads(lines[1])
            tampered["payload"] = {"value": 999}
            lines[1] = json.dumps(tampered)
            with open(audit_path, "w", encoding="utf-8") as audit_file:
                audit_file.write("\n".join(lines) + "\n")

            with self.assertRaises(AuditLogIntegrityError):
                AuditLogger(log_file_path=audit_path)

            failed_write_path = os.path.join(audit_dir, "failed-write.jsonl")
            failed_writer = AuditLogger(log_file_path=failed_write_path)
            event_count = len(failed_writer.events)
            hash_before_failure = failed_writer.latest_hash
            os.unlink(failed_write_path)
            os.mkdir(failed_write_path)
            with self.assertRaises(OSError):
                failed_writer.record_event("MUST_NOT_ADVANCE", "error")
            self.assertEqual(len(failed_writer.events), event_count)
            self.assertEqual(failed_writer.latest_hash, hash_before_failure)


if __name__ == "__main__":
    unittest.main()
