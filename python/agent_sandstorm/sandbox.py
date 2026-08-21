"""
sandbox.py: Master Sandstorm Orchestrator for Python
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import os
import time
import subprocess
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Any

from .cow import CoWSnapshotManager, Snapshot, RollbackResult
from .proxy import ZeroTrustProxy
from .limiter import ExecutionLimiter
from .audit import AuditLogger, export_timeline_ascii, generate_html_report


@dataclass
class SandboxResult:
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    rollback_performed: bool = False
    rollback_summary: Optional[RollbackResult] = None
    base_snapshot: Optional[Snapshot] = None
    duration_ms: float = 0.0
    audit_summary: Dict[str, Any] = field(default_factory=dict)
    spend_summary: Dict[str, Any] = field(default_factory=dict)


class Sandstorm:
    def __init__(
        self,
        workspace: str,
        allow_domains: Optional[List[str]] = None,
        block_domains: Optional[List[str]] = None,
        max_spend_usd: Optional[float] = None,
        max_tokens: Optional[int] = None,
        max_steps: int = 100,
        max_duration_ms: Optional[float] = None,
        auto_rollback_on_error: bool = True,
        scan_secrets: bool = True,
        audit_log_path: Optional[str] = None,
    ):
        self.workspace = os.path.abspath(workspace)
        self.auto_rollback = auto_rollback_on_error
        self.cow = CoWSnapshotManager(self.workspace)

        if not audit_log_path:
            audit_log_path = os.path.join(self.workspace, ".sandstorm", "audit.jsonl")

        self.audit = AuditLogger(log_file_path=audit_log_path)
        self.limiter = ExecutionLimiter(
            max_spend_usd=max_spend_usd,
            max_total_tokens=max_tokens,
            max_steps=max_steps,
            max_duration_ms=max_duration_ms,
        )

        allowed = allow_domains or ["api.openai.com", "api.anthropic.com", "pypi.org"]
        self.proxy = ZeroTrustProxy(
            allowed_domains=allowed,
            blocked_domains=block_domains,
            scan_payloads=scan_secrets,
            on_secret_detected=lambda d: self.audit.record_event(
                "SECRET_BLOCKED", "critical", {"pattern": d.pattern_name, "redacted": d.redacted_text}
            ),
        )

    def run(self, fn: Callable[[Any], Any]) -> SandboxResult:
        start_time = time.time()
        base_snap = self.cow.create_snapshot("pre-execution-baseline")
        self.audit.record_event("SNAPSHOT_CREATED", "info", {"id": base_snap.id, "tree_hash": base_snap.tree_hash})

        self.proxy.start()
        self.limiter.start()

        result_val = None
        exec_err: Optional[Exception] = None
        rollback_done = False
        rb_summary: Optional[RollbackResult] = None

        class Context:
            def __init__(ctx_self):
                ctx_self.workspace = self.workspace
                ctx_self.env = {**os.environ, **self.proxy.get_env()}

            def exec(ctx_self, command: str) -> subprocess.CompletedProcess:
                self.limiter.record_step(command.split()[0] if command.split() else command)
                self.audit.record_event("EXEC_STARTED", "info", {"cmd": command})
                res = subprocess.run(command, shell=True, cwd=self.workspace, env=ctx_self.env, capture_output=True, text=True)
                self.audit.record_event("EXEC_FINISHED", "info" if res.returncode == 0 else "warn", {"code": res.returncode})
                return res

            def record_tokens(ctx_self, model: str, p_tok: int, c_tok: int):
                usage = self.limiter.record_tokens(model, p_tok, c_tok)
                self.audit.record_event("BUDGET_ACCUMULATED", "info", usage)
                return usage

        ctx = Context()

        try:
            result_val = fn(ctx)
        except Exception as e:
            exec_err = e
            self.audit.record_event("CIRCUIT_BREAKER_TRIPPED", "critical", {"error": str(e)})
            if self.auto_rollback:
                rb_summary = self.cow.rollback(base_snap.id)
                rollback_done = True
                self.audit.record_event("ROLLBACK_TRIGGERED", "warn", {"restored": len(rb_summary.restored_files)})
        finally:
            self.proxy.stop()

        duration_ms = (time.time() - start_time) * 1000.0
        integrity = self.audit.verify_integrity()

        return SandboxResult(
            success=exec_err is None,
            result=result_val,
            error=exec_err,
            rollback_performed=rollback_done,
            rollback_summary=rb_summary,
            base_snapshot=base_snap,
            duration_ms=duration_ms,
            audit_summary={"verified": integrity["valid"], "events": len(self.audit.events)},
            spend_summary=self.limiter.get_summary(),
        )

    def snapshot(self, name: Optional[str] = None) -> Snapshot:
        return self.cow.create_snapshot(name)

    def rollback(self, snapshot_id: Optional[str] = None) -> RollbackResult:
        return self.cow.rollback(snapshot_id)

    def diff(self, snapshot_id: Optional[str] = None):
        return self.cow.diff(snapshot_id)

    def commit(self, name: Optional[str] = None) -> Snapshot:
        return self.cow.commit(name)

    def get_timeline(self) -> str:
        return export_timeline_ascii(self.audit.events)
