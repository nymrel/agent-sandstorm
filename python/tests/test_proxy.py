"""
Unit tests for Proxy & Secret Scanner (Python)
"""

import unittest
from agent_sandstorm.proxy import SecretScanner, DomainFilter


class TestProxy(unittest.TestCase):
    def test_secret_scanner(self):
        scanner = SecretScanner()
        text = "OpenAI key is sk-proj-1234567890abcdefghijklmnopqrstuvwxyz and AWS AKIAIOSFODNN7EXAMPLE"
        detections = scanner.scan(text)
        self.assertEqual(len(detections), 2)
        self.assertEqual(detections[0].pattern_name, "OpenAI API Key")
        self.assertEqual(detections[1].pattern_name, "AWS Access Key ID")

        redacted = scanner.redact_all(text)
        self.assertNotIn("sk-proj-1234567890", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)

    def test_domain_filter(self):
        filter_ = DomainFilter(["api.openai.com", "*.anthropic.com"], ["malicious.org"])
        self.assertTrue(filter_.is_allowed("api.openai.com"))
        self.assertTrue(filter_.is_allowed("sub.api.anthropic.com"))
        self.assertFalse(filter_.is_allowed("malicious.org"))
        self.assertFalse(filter_.is_allowed("unknown-site.xyz"))


if __name__ == "__main__":
    unittest.main()
