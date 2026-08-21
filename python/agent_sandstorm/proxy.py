"""
proxy.py: Outbound Network Filter & Zero-Trust Secret Exfiltration Scanner (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import re
import socket
import select
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable, Tuple, Any

BUILTIN_SECRET_PATTERNS = [
    (
        "OpenAI API Key",
        re.compile(r"sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}"),
        "OpenAI API secret key pattern",
        "critical",
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),
        "Anthropic API secret key pattern",
        "critical",
    ),
    (
        "AWS Access Key ID",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "AWS IAM access key ID",
        "critical",
    ),
    (
        "GitHub Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        "GitHub personal access or OAuth token",
        "critical",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "Google Cloud / Maps / Gemini API Key",
        "critical",
    ),
    (
        "Private Key (PEM)",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "Cryptographic private key file header",
        "critical",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
        "Slack API token",
        "high",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe live payment secret key",
        "critical",
    ),
    (
        "JSON Web Token (JWT)",
        re.compile(r"eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"),
        "Signed JSON Web Token credentials",
        "high",
    ),
]


def redact_secret(secret: str) -> str:
    if len(secret) <= 6:
        return "***[REDACTED]***"
    return f"{secret[:4]}...[REDACTED]...{secret[-2:]}"


@dataclass
class SecretDetection:
    pattern_name: str
    description: str
    severity: str
    matched_text: str
    redacted_text: str
    location: str
    timestamp: float


class SecretScanner:
    def __init__(self, custom_patterns: Optional[List[Tuple[str, Any, str, str]]] = None):
        self.patterns = BUILTIN_SECRET_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def scan(self, text: str, location: str = "body") -> List[SecretDetection]:
        if not text or not isinstance(text, str):
            return []

        detections: List[SecretDetection] = []
        for name, regex, desc, severity in self.patterns:
            for match in regex.finditer(text):
                matched = match.group(0)
                detections.append(
                    SecretDetection(
                        pattern_name=name,
                        description=desc,
                        severity=severity,
                        matched_text=matched,
                        redacted_text=redact_secret(matched),
                        location=location,
                        timestamp=0.0,
                    )
                )
        return detections

    def redact_all(self, text: str) -> str:
        if not text:
            return text
        result = text
        for _, regex, _, _ in self.patterns:
            result = regex.sub(lambda m: redact_secret(m.group(0)), result)
        return result


class DomainFilter:
    def __init__(self, allowed_domains: Optional[List[str]] = None, blocked_domains: Optional[List[str]] = None):
        self.allowed_regexes = [self._domain_to_regex(d) for d in (allowed_domains or [])]
        self.blocked_regexes = [self._domain_to_regex(d) for d in (blocked_domains or [])]

    def _domain_to_regex(self, pattern: str) -> re.Pattern:
        trimmed = pattern.strip().lower()
        escaped = trimmed.replace(".", r"\.").replace("*", r"[a-zA-Z0-9_-]+")
        return re.compile(rf"^(?:.+\.)?{escaped}$", re.IGNORECASE)

    def is_allowed(self, host_header: str) -> bool:
        if not host_header:
            return False
        clean_host = host_header.split(":")[0].lower()

        # Check denylist
        for regex in self.blocked_regexes:
            if regex.match(clean_host):
                return False

        # Zero-Trust: must match allowlist
        if not self.allowed_regexes:
            return False

        for regex in self.allowed_regexes:
            if regex.match(clean_host):
                return True

        return False


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunnels"""
        host_port = self.path
        target_host = host_port.split(":")[0]
        target_port = int(host_port.split(":")[1]) if ":" in host_port else 443

        if not self.server.filter.is_allowed(target_host):
            self.send_response(403, "Forbidden")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            body = b'{"error":"ERR_SANDSTORM_DOMAIN_BLOCKED","policy":"Zero-Trust Domain Allowlist"}\n'
            self.wfile.write(body)
            return

        try:
            target_sock = socket.create_connection((target_host, target_port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()

            # Pipe sockets
            sockets = [self.connection, target_sock]
            while True:
                r, _, _ = select.select(sockets, [], [], 10)
                if not r:
                    break
                for s in r:
                    other = target_sock if s is self.connection else self.connection
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            self.send_error(502, "Bad Gateway")

    def do_GET(self):
        self._handle_http_forward()

    def do_POST(self):
        self._handle_http_forward()

    def do_PUT(self):
        self._handle_http_forward()

    def do_DELETE(self):
        self._handle_http_forward()

    def do_PATCH(self):
        self._handle_http_forward()

    def _handle_http_forward(self):
        parsed = urllib.parse.urlparse(self.path)
        target_host = self.headers.get("Host") or parsed.netloc

        if not self.server.filter.is_allowed(target_host):
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"ERR_SANDSTORM_DOMAIN_BLOCKED"}\n')
            return

        # Check secrets in URL
        if self.server.scan_payloads:
            url_secrets = self.server.scanner.scan(self.path, "url")
            if url_secrets:
                self._block_secret(url_secrets[0], target_host)
                return

        # Read body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.server.scan_payloads and body:
            try:
                body_text = body.decode("utf-8", errors="ignore")
                body_secrets = self.server.scanner.scan(body_text, "body")
                if body_secrets:
                    self._block_secret(body_secrets[0], target_host)
                    return
            except Exception:
                pass

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","sandstorm_verified":true}\n')

    def _block_secret(self, detection: SecretDetection, target_host: str):
        if self.server.on_secret_detected:
            self.server.on_secret_detected(detection)

        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        msg = f'{{"error":"ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED","pattern":"{detection.pattern_name}","redacted":"{detection.redacted_text}"}}\n'.encode("utf-8")
        self.wfile.write(msg)

    def log_message(self, format, *args):
        pass  # Suppress default noisy console logs


class ZeroTrustProxy:
    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
        port: int = 0,
        host: str = "127.0.0.1",
        scan_payloads: bool = True,
        on_secret_detected: Optional[Callable[[SecretDetection], None]] = None,
    ):
        self.host = host
        self.port = port
        self.scan_payloads = scan_payloads
        self.scanner = SecretScanner()
        self.filter = DomainFilter(allowed_domains or [], blocked_domains or [])
        self.on_secret_detected = on_secret_detected
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> Tuple[str, int]:
        self.server = HTTPServer((self.host, self.port), ProxyRequestHandler)
        # Attach configuration to server instance
        self.server.filter = self.filter
        self.server.scanner = self.scanner
        self.server.scan_payloads = self.scan_payloads
        self.server.on_secret_detected = self.on_secret_detected

        self.port = self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self.port

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def get_env(self) -> Dict[str, str]:
        proxy_url = f"http://{self.host}:{self.port}"
        return {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
            "no_proxy": "localhost,127.0.0.1",
        }
