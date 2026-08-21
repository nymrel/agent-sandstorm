"""
agent_sandstorm: Zero-Trust Agent Execution Sandbox & Copy-on-Write Workspace Isolation Engine.
Copyright 2026 Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
MIT License
"""

from .cow import CoWSnapshotManager, Snapshot, RollbackResult, WorkspaceDiff
from .proxy import ZeroTrustProxy, SecretScanner, SecretDetection
from .limiter import ExecutionLimiter, BudgetTracker, LoopDetector, BudgetExceededError, RunawayLoopError
from .audit import AuditLogger, AuditEvent, export_timeline_ascii, generate_html_report
from .sandbox import Sandstorm, SandboxResult

__version__ = "1.0.0"
__author__ = "Nymrel / JalenBuilds LLC"
__all__ = [
    "Sandstorm",
    "SandboxResult",
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
    "export_timeline_ascii",
    "generate_html_report",
]
