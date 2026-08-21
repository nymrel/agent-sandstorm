"""
audit.py: Cryptographic SHA-256 Audit Logger & Timeline Exporter (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import os
import json
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_event_hash(
    index: int,
    prev_hash: str,
    timestamp: float,
    event_type: str,
    severity: str,
    payload: Dict[str, Any],
) -> str:
    sorted_payload = json.dumps(payload, sort_keys=True)
    raw = f"{index}|{prev_hash}|{timestamp}|{event_type}|{severity}|{sorted_payload}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class AuditEvent:
    index: int
    prev_hash: str
    hash: str
    timestamp: float
    iso_time: str
    type: str
    severity: str
    payload: Dict[str, Any]


class AuditLogger:
    def __init__(self, log_file_path: Optional[str] = None, initial_payload: Optional[Dict[str, Any]] = None):
        self.log_file_path = log_file_path
        self.events: List[AuditEvent] = []
        self.latest_hash = GENESIS_PREV_HASH

        if self.log_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_file_path)), exist_ok=True)

        payload = {"version": "1.0.0", "engine": "agent-sandstorm-py"}
        if initial_payload:
            payload.update(initial_payload)

        self.record_event("SANDBOX_INIT", "info", payload)

    def record_event(self, event_type: str, severity: str = "info", payload: Optional[Dict[str, Any]] = None) -> AuditEvent:
        if payload is None:
            payload = {}

        idx = len(self.events)
        ts = time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        prev = self.latest_hash
        ev_hash = compute_event_hash(idx, prev, ts, event_type, severity, payload)

        ev = AuditEvent(
            index=idx,
            prev_hash=prev,
            hash=ev_hash,
            timestamp=ts,
            iso_time=iso,
            type=event_type,
            severity=severity,
            payload=payload,
        )

        self.events.append(ev)
        self.latest_hash = ev_hash

        if self.log_file_path:
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(ev)) + "\n")
            except Exception:
                pass

        return ev

    def verify_integrity(self) -> Dict[str, Any]:
        if not self.events:
            return {"valid": True, "event_count": 0}

        expected_prev = GENESIS_PREV_HASH
        for i, ev in enumerate(self.events):
            if ev.index != i:
                return {"valid": False, "corrupted_index": i, "reason": "Index mismatch"}
            if ev.prev_hash != expected_prev:
                return {"valid": False, "corrupted_index": i, "reason": "PrevHash mismatch"}

            computed = compute_event_hash(
                ev.index, ev.prev_hash, ev.timestamp, ev.type, ev.severity, ev.payload
            )
            if computed != ev.hash:
                return {"valid": False, "corrupted_index": i, "reason": "Hash signature mismatch"}

            expected_prev = ev.hash

        return {"valid": True, "event_count": len(self.events), "latest_hash": self.latest_hash}


def export_timeline_ascii(events: List[AuditEvent]) -> str:
    lines = [
        "═" * 80,
        "  🛡️  SANDSTORM EXECUTION AUDIT TIMELINE (PYTHON)",
        "═" * 80,
        f"  Total Events: {len(events)}  |  SHA-256 Chain Verified",
        "─" * 80,
    ]

    for i, ev in enumerate(events):
        badge = f"[{ev.severity.upper():^6}]"
        time_part = ev.iso_time[11:19]
        is_last = i == len(events) - 1
        branch = "└──" if is_last else "├──"
        pipe = "   " if is_last else "│  "

        lines.append(f" {branch} [{time_part}] {badge} {ev.type:<20} {str(ev.payload)[:50]}")
        lines.append(f" {pipe}     Hash: {ev.hash[:16]}... | Prev: {ev.prev_hash[:16]}...")
        if not is_last:
            lines.append(" │")

    lines.append("═" * 80)
    return "\n".join(lines)


def generate_html_report(events: List[AuditEvent], integrity: Dict[str, Any], workspace: str) -> str:
    events_json = json.dumps([asdict(e) for e in events], indent=2)
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sandstorm Audit Report - {workspace}</title>
  <style>
    body {{ font-family: sans-serif; background: #FAF8F2; color: #2A332E; padding: 2rem; }}
    .card {{ background: #FFF; border: 1px solid #E5E0D4; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
    h1 {{ color: #2A332E; }}
    pre {{ background: #F4F0E6; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>🛡️ Sandstorm Audit Report</h1>
  <div class="card">
    <p><strong>Workspace:</strong> {workspace}</p>
    <p><strong>Verified:</strong> {'✅ Yes' if integrity.get('valid') else '❌ Tamper Detected'}</p>
    <p><strong>Total Events:</strong> {len(events)}</p>
  </div>
  <div class="card">
    <h2>Audit Events (JSON)</h2>
    <pre>{events_json}</pre>
  </div>
</body>
</html>"""
