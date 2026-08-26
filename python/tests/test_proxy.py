"""
Unit tests for Proxy & Secret Scanner (Python)
"""

import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent_sandstorm.proxy import SecretScanner, DomainFilter, ZeroTrustProxy


class TestProxy(unittest.TestCase):
    def test_secret_scanner(self):
        scanner = SecretScanner()
        text = "OpenAI key is sk-proj-1234567890abcdefghijklmnopqrstuvwxyz and AWS AKIAIOSFODNN7EXAMPLE"
        detections = scanner.scan(text)
        self.assertEqual(len(detections), 2)
        anthropic = scanner.scan("sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(len(anthropic), 1)
        self.assertEqual(anthropic[0].pattern_name, "Anthropic API Key")
        self.assertEqual(detections[0].pattern_name, "OpenAI API Key")
        self.assertEqual(detections[1].pattern_name, "AWS Access Key ID")

        redacted = scanner.redact_all(text)
        self.assertNotIn("sk-proj-1234567890", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)

    def test_domain_filter(self):
        filter_ = DomainFilter(
            ["api.openai.com", "*.anthropic.com", "*.*.anthropic.com"],
            ["malicious.org"],
        )
        self.assertTrue(filter_.is_allowed("api.openai.com"))
        self.assertFalse(filter_.is_allowed("sub.api.openai.com"))
        self.assertTrue(filter_.is_allowed("sub.api.anthropic.com"))
        self.assertTrue(filter_.is_allowed("v1.api.anthropic.com"))
        self.assertTrue(filter_.is_allowed("api.openai.com:443"))
        self.assertTrue(filter_.is_allowed("api.openai.com."))
        self.assertFalse(filter_.is_allowed("malicious.org"))
        self.assertFalse(filter_.is_allowed("unknown-site.xyz"))
        with self.assertRaises(ValueError):
            DomainFilter(["api.openai.com$|evil.example"])

    def test_plain_http_forwarding_and_header_secret_blocking(self):
        class UpstreamHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"upstream-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        upstream = HTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        proxy = ZeroTrustProxy(allowed_domains=["127.0.0.1"])
        proxy.start()

        try:
            connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            target = f"http://127.0.0.1:{upstream.server_port}/health"
            connection.request("GET", target, headers={"Host": f"127.0.0.1:{upstream.server_port}"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"upstream-ok")
            connection.close()

            secret = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
            connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            connection.request(
                "GET",
                target,
                headers={
                    "Host": f"127.0.0.1:{upstream.server_port}",
                    "X-Debug-Token": secret,
                },
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            self.assertIn(b"ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED", response.read())
            connection.close()
        finally:
            proxy.stop()
            with self.assertRaises(RuntimeError):
                proxy.get_env()

            mismatch_proxy = ZeroTrustProxy(allowed_domains=["allowed.example"])
            mismatch_proxy.start()
            try:
                mismatch_connection = http.client.HTTPConnection(
                    "127.0.0.1", mismatch_proxy.port, timeout=5
                )
                mismatch_connection.request(
                    "GET",
                    f"http://127.0.0.1:{upstream.server_port}/must-not-forward",
                    headers={"Host": "allowed.example"},
                )
                mismatch_response = mismatch_connection.getresponse()
                self.assertEqual(mismatch_response.status, 403)
                mismatch_response.read()
                mismatch_connection.close()
            finally:
                mismatch_proxy.stop()

            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    unittest.main()
