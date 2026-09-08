"""
audit.py: Cryptographic SHA-256 Audit Logger & Timeline Exporter (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import os
import json
import time
import hashlib
import html
import math
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
AUDIT_SEVERITIES = {"info", "warn", "error", "critical"}


class AuditLogIntegrityError(RuntimeError):
    """Raised when a persisted audit log cannot be resumed safely."""


def _serialize_payload(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, allow_nan=False)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value {value}")


def _validate_event_shape(event: "AuditEvent") -> None:
    if isinstance(event.index, bool) or not isinstance(event.index, int) or event.index < 0:
        raise AuditLogIntegrityError("Audit event index must be a nonnegative integer")
    if not isinstance(event.prev_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", event.prev_hash):
        raise AuditLogIntegrityError("Audit event prev_hash must be a lowercase SHA-256 digest")
    if not isinstance(event.hash, str) or not re.fullmatch(r"[a-f0-9]{64}", event.hash):
        raise AuditLogIntegrityError("Audit event hash must be a lowercase SHA-256 digest")
    if (
        isinstance(event.timestamp, bool)
        or not isinstance(event.timestamp, (int, float))
        or not math.isfinite(event.timestamp)
    ):
        raise AuditLogIntegrityError("Audit event timestamp must be finite")
    if not isinstance(event.iso_time, str):
        raise AuditLogIntegrityError("Audit event iso_time must be a string")
    if not isinstance(event.type, str) or not event.type.strip():
        raise AuditLogIntegrityError("Audit event type must not be empty")
    if event.severity not in AUDIT_SEVERITIES:
        raise AuditLogIntegrityError("Audit event severity is invalid")
    if not isinstance(event.payload, dict):
        raise AuditLogIntegrityError("Audit event payload must be an object")
    try:
        _serialize_payload(event.payload)
        expected_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.timestamp))
    except (TypeError, ValueError, OverflowError, OSError) as error:
        raise AuditLogIntegrityError(f"Audit event contains non-JSON or invalid values: {error}") from error
    if event.iso_time != expected_iso:
        raise AuditLogIntegrityError("Audit event iso_time does not match its timestamp")


def compute_event_hash(
    index: int,
    prev_hash: str,
    timestamp: float,
    event_type: str,
    severity: str,
    payload: Dict[str, Any],
) -> str:
    sorted_payload = _serialize_payload(payload)
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
        resumed = False

        if self.log_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_file_path)), exist_ok=True)
            if os.path.exists(self.log_file_path) and os.path.getsize(self.log_file_path) > 0:
                self._load_persisted_events()
                integrity = self.verify_integrity()
                if not integrity["valid"]:
                    raise AuditLogIntegrityError(
                        f"Refusing to append to an invalid audit chain at event "
                        f"{integrity.get('corrupted_index', 'unknown')}"
                    )
                resumed = True

        payload = {"version": "0.1.0", "engine": "agent-sandstorm-py"}
        if initial_payload:
            payload.update(initial_payload)

        self.record_event("SANDBOX_RESUME" if resumed else "SANDBOX_INIT", "info", payload)

    def _load_persisted_events(self) -> None:
        try:
            with open(self.log_file_path, encoding="utf-8") as audit_file:
                lines = [line for line in audit_file.read().splitlines() if line.strip()]
            loaded = []
            for line_number, line in enumerate(lines, start=1):
                try:
                    raw = json.loads(line, parse_constant=_reject_json_constant)
                    event = AuditEvent(**raw)
                except (json.JSONDecodeError, TypeError, ValueError) as error:
                    raise AuditLogIntegrityError(
                        f"Audit log line {line_number} has an invalid event: {error}"
                    ) from error
                try:
                    _validate_event_shape(event)
                except AuditLogIntegrityError as error:
                    raise AuditLogIntegrityError(f"Audit log line {line_number} is invalid: {error}") from error
                loaded.append(event)
        except OSError as error:
            raise AuditLogIntegrityError(f"Could not read audit log: {error}") from error

        self.events = loaded
        self.latest_hash = loaded[-1].hash if loaded else GENESIS_PREV_HASH

    def record_event(self, event_type: str, severity: str = "info", payload: Optional[Dict[str, Any]] = None) -> AuditEvent:
        if payload is None:
            payload = {}
        if not isinstance(event_type, str) or not event_type.strip():
            raise TypeError("Audit event type must not be empty")
        if severity not in AUDIT_SEVERITIES:
            raise ValueError(f"Invalid audit severity: {severity}")
        if not isinstance(payload, dict):
            raise TypeError("Audit event payload must be an object")

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

        if self.log_file_path:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(ev), allow_nan=False) + "\n")

        # Do not advance in-memory state unless persistence succeeded.
        self.events.append(ev)
        self.latest_hash = ev_hash

        return ev

    def verify_integrity(self) -> Dict[str, Any]:
        if not self.events:
            return {"valid": True, "event_count": 0}

        expected_prev = GENESIS_PREV_HASH
        for i, ev in enumerate(self.events):
            try:
                _validate_event_shape(ev)
            except AuditLogIntegrityError as error:
                return {"valid": False, "corrupted_index": i, "reason": str(error)}
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
        f"  Total Events: {len(events)}  |  SHA-256 hash-chained (not externally authenticated)",
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
    events_json = html.escape(json.dumps([asdict(e) for e in events], indent=2, allow_nan=False))
    escaped_workspace = html.escape(str(workspace))
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sandstorm Audit Report - {escaped_workspace}</title>
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
    <p><strong>Workspace:</strong> {escaped_workspace}</p>
    <p><strong>Verified:</strong> {'✅ Yes' if integrity.get('valid') else '❌ Tamper Detected'}</p>
    <p><strong>Total Events:</strong> {len(events)}</p>
  </div>
  <div class="card">
    <h2>Audit Events (JSON)</h2>
    <pre>{events_json}</pre>
  </div>
</body>
</html>"""
