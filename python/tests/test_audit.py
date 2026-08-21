"""
Unit tests for Cryptographic Audit Logger (Python)
"""

import unittest
from agent_sandstorm.audit import AuditLogger, export_timeline_ascii, generate_html_report


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

    def test_timeline_and_html(self):
        logger = AuditLogger()
        logger.record_event("TEST_EVENT", "info", {"data": 123})
        timeline = export_timeline_ascii(logger.events)
        self.assertIn("SANDSTORM", timeline)

        html = generate_html_report(logger.events, logger.verify_integrity(), "/workspace")
        self.assertIn("Sandstorm Audit Report", html)


if __name__ == "__main__":
    unittest.main()
