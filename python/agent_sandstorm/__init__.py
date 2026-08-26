"""
agent_sandstorm: Experimental agent execution guardrails and workspace recovery tools.
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

from .cow import CoWSnapshotManager, Snapshot, RollbackResult, WorkspaceDiff
from .proxy import ZeroTrustProxy, SecretScanner, SecretDetection
from .limiter import ExecutionLimiter, BudgetTracker, LoopDetector, BudgetExceededError, RunawayLoopError
from .audit import AuditLogger, AuditEvent, AuditLogIntegrityError, export_timeline_ascii, generate_html_report
from .sandbox import Sandstorm, SandboxResult, CommandExecutionError

__version__ = "0.1.0"
__author__ = "Nymrel / JalenBuilds LLC"
__all__ = [
    "Sandstorm",
    "SandboxResult",
    "CommandExecutionError",
    "CoWSnapshotManager",
    "Snapshot",
    "RollbackResult",
    "WorkspaceDiff",
    "ZeroTrustProxy",
    "SecretScanner",
    "SecretDetection",
    "ExecutionLimiter",
    "BudgetTracker",
    "LoopDetector",
    "BudgetExceededError",
    "RunawayLoopError",
    "AuditLogger",
    "AuditEvent",
    "AuditLogIntegrityError",
    "export_timeline_ascii",
    "generate_html_report",
]
