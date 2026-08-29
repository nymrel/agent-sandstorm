"""
Unit tests for Proxy & Secret Scanner (Python)
"""

import http.client
import socket
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
                self.send_header("Connection", "x-response-remove, close")
                self.send_header("X-Response-Remove", "response-leaked")
                self.send_header("X-Response-Keep", "response-kept")
                self.send_header("Trailer", "Expires")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        upstream = HTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        proxy = ZeroTrustProxy(
            allowed_domains=["127.0.0.1"],
            allowed_ports=[upstream.server_port],
        )
        proxy.start()

        try:
            connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            target = f"http://127.0.0.1:{upstream.server_port}/health"
            connection.request("GET", target, headers={"Host": f"127.0.0.1:{upstream.server_port}"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"upstream-ok")
            self.assertIsNone(response.getheader("X-Response-Remove"))
            self.assertIsNone(response.getheader("Trailer"))
            self.assertEqual(response.getheader("X-Response-Keep"), "response-kept")
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

            mismatch_proxy = ZeroTrustProxy(
                allowed_domains=["allowed.example"],
                allowed_ports=[upstream.server_port],
            )
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

    def test_destination_port_policy_fails_closed_before_dial(self):
        decoy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        decoy.bind(("127.0.0.1", 0))
        decoy.listen()
        decoy.settimeout(0.1)
        decoy_port = decoy.getsockname()[1]
        decoy_hits = []
        decoy_stop = threading.Event()

        def accept_decoy_connections():
            while not decoy_stop.is_set():
                try:
                    connection, _ = decoy.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                decoy_hits.append(True)
                connection.close()

        decoy_thread = threading.Thread(target=accept_decoy_connections, daemon=True)
        decoy_thread.start()
        blocked_ports = []
        proxy = ZeroTrustProxy(
            allowed_domains=["127.0.0.1"],
            on_blocked_port=lambda host, port, url: blocked_ports.append((host, port, url)),
        )
        proxy.start()

        def raw_connect(authority):
            with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as connection:
                request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
                connection.sendall(request.encode("ascii"))
                connection.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)

        try:
            self.assertEqual(proxy.get_allowed_ports(), [80, 443])
            with self.assertRaises(ValueError):
                ZeroTrustProxy(allowed_domains=["127.0.0.1"], allowed_ports=[])
            with self.assertRaises(ValueError):
                ZeroTrustProxy(allowed_domains=["127.0.0.1"], allowed_ports=[443, 70000])

            connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            connection.request("GET", f"http://127.0.0.1:{decoy_port}/blocked")
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            self.assertIn(b"ERR_SANDSTORM_PORT_BLOCKED", response.read())
            connection.close()

            connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            connection.request("GET", "http://127.0.0.1:/blocked")
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            self.assertIn(b"ERR_SANDSTORM_PORT_BLOCKED", response.read())
            connection.close()

            connect_block = raw_connect(f"127.0.0.1:{decoy_port}")
            self.assertIn(b"403", connect_block)
            self.assertIn(b"ERR_SANDSTORM_PORT_BLOCKED", connect_block)

            malformed_block = raw_connect("127.0.0.1:not-a-port")
            self.assertIn(b"403", malformed_block)
            self.assertIn(b"ERR_SANDSTORM_PORT_BLOCKED", malformed_block)
            self.assertFalse(decoy_stop.wait(0.2))
            self.assertEqual(decoy_hits, [])
            self.assertEqual(len(blocked_ports), 4)
        finally:
            proxy.stop()
            decoy_stop.set()
            decoy.close()
            decoy_thread.join(timeout=1)

        class ApprovedHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"decoy-hit"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        approved = HTTPServer(("127.0.0.1", 0), ApprovedHandler)
        approved_thread = threading.Thread(target=approved.serve_forever, daemon=True)
        approved_thread.start()
        approved_proxy = ZeroTrustProxy(
            allowed_domains=["127.0.0.1"],
            allowed_ports=[approved.server_port],
        )
        approved_proxy.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", approved_proxy.port, timeout=5)
            connection.request("GET", f"http://127.0.0.1:{approved.server_port}/allowed")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"decoy-hit")
            connection.close()
        finally:
            approved_proxy.stop()
            approved.shutdown()
            approved.server_close()


if __name__ == "__main__":
    unittest.main()
