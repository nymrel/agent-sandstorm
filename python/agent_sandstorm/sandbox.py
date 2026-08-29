"""
sandbox.py: Master Sandstorm Orchestrator for Python
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import os
import shlex
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
    final_tree_hash: str = ""
    duration_ms: float = 0.0
    audit_summary: Dict[str, Any] = field(default_factory=dict)
    spend_summary: Dict[str, Any] = field(default_factory=dict)


class CommandExecutionError(RuntimeError):
    """Raised when a guarded child command exits unsuccessfully."""

    def __init__(self, command: str, execution: subprocess.CompletedProcess):
        super().__init__(f"Command exited with code {execution.returncode}: {command}")
        self.command = command
        self.execution = execution


class Sandstorm:
    def __init__(
        self,
        workspace: str,
        allow_domains: Optional[List[str]] = None,
        block_domains: Optional[List[str]] = None,
        allow_ports: Optional[List[int]] = None,
        max_spend_usd: Optional[float] = None,
        max_tokens: Optional[int] = None,
        max_steps: int = 100,
        max_duration_ms: Optional[float] = None,
        auto_rollback_on_error: bool = True,
        detect_runaway_loops: bool = True,
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
            loop_detection=detect_runaway_loops,
        )

        allowed = allow_domains if allow_domains is not None else []
        self.proxy = ZeroTrustProxy(
            allowed_domains=allowed,
            blocked_domains=block_domains,
            allowed_ports=allow_ports,
            scan_payloads=scan_secrets,
            on_secret_detected=lambda d: self.audit.record_event(
                "SECRET_BLOCKED", "critical", {"pattern": d.pattern_name, "redacted": d.redacted_text}
            ),
            on_blocked_port=lambda host, port, url: self.audit.record_event(
                "PORT_BLOCKED",
                "warn",
                {
                    "host": self.proxy.scanner.redact_all(host),
                    "port": "invalid" if port is None else port,
                    "url": self.proxy.scanner.redact_all(url),
                },
            ),
        )

    def run(self, fn: Callable[[Any], Any]) -> SandboxResult:
        start_time = time.time()
        self.limiter.reset()
        base_snap = self.cow.create_snapshot("pre-execution-baseline")
        self.audit.record_event("SNAPSHOT_CREATED", "info", {"id": base_snap.id, "tree_hash": base_snap.tree_hash})

        self.proxy.start()
        result_val = None
        exec_err: Optional[Exception] = None
        rollback_done = False
        rb_summary: Optional[RollbackResult] = None

        class Context:
            def __init__(ctx_self):
                ctx_self.workspace = self.workspace
                ctx_self.env = {**os.environ, **self.proxy.get_env()}

            def exec(ctx_self, command, allow_nonzero: bool = False, shell: bool = False) -> subprocess.CompletedProcess:
                if isinstance(command, str):
                    display_command = command
                    invocation = command if shell else shlex.split(command, posix=os.name != "nt")
                else:
                    if shell:
                        raise TypeError("shell=True requires a command string")
                    invocation = [str(part) for part in command]
                    display_command = shlex.join(invocation)

                if not invocation:
                    raise ValueError("command must not be empty")

                action_name = invocation.split()[0] if isinstance(invocation, str) else invocation[0]
                self.limiter.record_step(action_name, display_command)
                redacted_command = self.proxy.scanner.redact_all(display_command)
                self.audit.record_event("EXEC_STARTED", "info", {"cmd": redacted_command, "shell": shell})
                # shell=True is permitted only through the explicit caller opt-in above.
                res = subprocess.run(
                    invocation,
                    shell=shell,  # nosec B602
                    cwd=self.workspace,
                    env=ctx_self.env,
                    capture_output=True,
                    text=True,
                )
                self.audit.record_event("EXEC_FINISHED", "info" if res.returncode == 0 else "warn", {"code": res.returncode})
                if res.returncode != 0 and not allow_nonzero:
                    redacted_execution = subprocess.CompletedProcess(
                        args=redacted_command,
                        returncode=res.returncode,
                        stdout=self.proxy.scanner.redact_all(res.stdout),
                        stderr=self.proxy.scanner.redact_all(res.stderr),
                    )
                    raise CommandExecutionError(redacted_command, redacted_execution)
                return res

            def record_tokens(ctx_self, model: str, p_tok: int, c_tok: int):
                usage = self.limiter.record_tokens(model, p_tok, c_tok)
                self.audit.record_event(
                    "BUDGET_ACCUMULATED",
                    "info",
                    {**usage, "model": self.proxy.scanner.redact_all(model)},
                )
                return usage

        ctx = Context()

        try:
            result_val = fn(ctx)
        except Exception as e:
            exec_err = e
            self.audit.record_event(
                "CIRCUIT_BREAKER_TRIPPED",
                "critical",
                {"error": self.proxy.scanner.redact_all(str(e))},
            )
            if self.auto_rollback:
                rb_summary = self.cow.rollback(base_snap.id)
                rollback_done = True
                self.audit.record_event(
                    "ROLLBACK_TRIGGERED",
                    "warn",
                    {
                        "success": rb_summary.success,
                        "restored": len(rb_summary.restored_files),
                        "deleted": len(rb_summary.deleted_files),
                        "reverted": len(rb_summary.reverted_files),
                        "duration_ms": rb_summary.duration_ms,
                        "error": rb_summary.error,
                    },
                )
        finally:
            self.proxy.stop()

        duration_ms = (time.time() - start_time) * 1000.0
        integrity = self.audit.verify_integrity()
        final_tree_hash = self.cow.create_snapshot("final-state").tree_hash

        return SandboxResult(
            success=exec_err is None,
            result=result_val,
            error=exec_err,
            rollback_performed=rollback_done,
            rollback_summary=rb_summary,
            base_snapshot=base_snap,
            final_tree_hash=final_tree_hash,
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
