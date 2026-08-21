"""
cow.py: Copy-on-Write Workspace Isolation Engine (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import os
import sys
import json
import time
import shutil
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Any

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".sandstorm",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".cache",
}

DEFAULT_IGNORED_FILES = {
    ".DS_Store",
    "Thumbs.db",
}


@dataclass
class FileSnapshot:
    path: str
    relative_path: str
    sha256: str
    size: int
    mtime_ms: float
    mode: int = 0o644


@dataclass
class Snapshot:
    id: str
    name: str
    timestamp: float
    iso_time: str
    workspace_path: str
    file_count: int
    total_size_bytes: int
    tree_hash: str
    files: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RollbackResult:
    success: bool = True
    snapshot_id: str = ""
    restored_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    reverted_files: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class WorkspaceDiff:
    base_snapshot_id: str
    added: List[str]
    modified: List[str]
    deleted: List[str]
    unchanged_count: int
    total_changed: int


def compute_file_sha256(file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_tree_hash(files: Dict[str, FileSnapshot]) -> str:
    hasher = hashlib.sha256()
    for rel_path in sorted(files.keys()):
        f = files[rel_path]
        hasher.update(f"{rel_path}:{f.sha256}:{f.size}\n".encode("utf-8"))
    return hasher.hexdigest()


def scan_workspace(
    workspace_root: str,
    ignored_dirs: Optional[Set[str]] = None,
    ignored_files: Optional[Set[str]] = None,
) -> Dict[str, FileSnapshot]:
    if ignored_dirs is None:
        ignored_dirs = DEFAULT_IGNORED_DIRS
    if ignored_files is None:
        ignored_files = DEFAULT_IGNORED_FILES

    result: Dict[str, FileSnapshot] = {}
    if not os.path.exists(workspace_root):
        return result

    for root, dirs, filenames in os.walk(workspace_root):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".sandstorm")]

        for fname in filenames:
            if fname in ignored_files:
                continue

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, workspace_root).replace("\\", "/")

            try:
                stat = os.stat(full_path)
                sha = compute_file_sha256(full_path)
                result[rel_path] = FileSnapshot(
                    path=full_path,
                    relative_path=rel_path,
                    sha256=sha,
                    size=stat.st_size,
                    mtime_ms=stat.st_mtime * 1000.0,
                    mode=stat.st_mode,
                )
            except (OSError, IOError):
                pass

    return result


class ObjectStore:
    def __init__(self, sandstorm_dir: str):
        self.store_root = os.path.join(sandstorm_dir, "objects")
        os.makedirs(self.store_root, exist_ok=True)

    def get_object_path(self, sha256: str) -> str:
        prefix = sha256[:2]
        return os.path.join(self.store_root, prefix, sha256)

    def put_file(self, src_path: str, sha256: str) -> None:
        dest = self.get_object_path(sha256)
        if not os.path.exists(dest):
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(src_path, dest)

    def get_file_content(self, sha256: str) -> bytes:
        dest = self.get_object_path(sha256)
        if not os.path.exists(dest):
            raise FileNotFoundError(f"Object not found in store: {sha256}")
        with open(dest, "rb") as f:
            return f.read()


class CoWSnapshotManager:
    def __init__(self, workspace_root: str, sandstorm_dir: Optional[str] = None):
        self.workspace_root = os.path.abspath(workspace_root)
        self.sandstorm_dir = (
            os.path.abspath(sandstorm_dir)
            if sandstorm_dir
            else os.path.join(self.workspace_root, ".sandstorm")
        )
        self.snapshots_dir = os.path.join(self.sandstorm_dir, "snapshots")
        os.makedirs(self.snapshots_dir, exist_ok=True)
        self.object_store = ObjectStore(self.sandstorm_dir)
        self._latest_snapshot: Optional[Snapshot] = None

    def create_snapshot(self, name: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Snapshot:
        timestamp = time.time()
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
        snap_id = f"snap_{int(timestamp * 1000)}_{os.urandom(3).hex()}"

        files = scan_workspace(self.workspace_root)
        total_size = sum(f.size for f in files.values())

        for f in files.values():
            self.object_store.put_file(f.path, f.sha256)

        tree_hash = compute_tree_hash(files)
        files_dict = {rel: asdict(f) for rel, f in files.items()}

        snapshot = Snapshot(
            id=snap_id,
            name=name or f"Snapshot {iso_time}",
            timestamp=timestamp,
            iso_time=iso_time,
            workspace_path=self.workspace_root,
            file_count=len(files),
            total_size_bytes=total_size,
            tree_hash=tree_hash,
            files=files_dict,
            metadata=metadata or {},
        )

        snap_path = os.path.join(self.snapshots_dir, f"{snap_id}.json")
        with open(snap_path, "w", encoding="utf-8") as f:
            json.dump(asdict(snapshot), f, indent=2)

        curr_path = os.path.join(self.snapshots_dir, "current.json")
        with open(curr_path, "w", encoding="utf-8") as f:
            json.dump({"id": snap_id, "tree_hash": tree_hash, "timestamp": timestamp}, f, indent=2)

        self._latest_snapshot = snapshot
        return snapshot

    def get_snapshot(self, snap_id: Optional[str] = None) -> Optional[Snapshot]:
        if not snap_id:
            if self._latest_snapshot:
                return self._latest_snapshot
            curr_path = os.path.join(self.snapshots_dir, "current.json")
            if os.path.exists(curr_path):
                try:
                    with open(curr_path, "r", encoding="utf-8") as f:
                        curr = json.load(f)
                    return self.get_snapshot(curr.get("id"))
                except Exception:
                    return None
            return None

        snap_path = os.path.join(self.snapshots_dir, f"{snap_id}.json")
        if not os.path.exists(snap_path):
            return None

        try:
            with open(snap_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return Snapshot(**data)
        except Exception:
            return None

    def list_snapshots(self) -> List[Snapshot]:
        if not os.path.exists(self.snapshots_dir):
            return []
        snapshots: List[Snapshot] = []
        for fname in os.listdir(self.snapshots_dir):
            if fname.startswith("snap_") and fname.endswith(".json"):
                snap = self.get_snapshot(fname[:-5])
                if snap:
                    snapshots.append(snap)
        snapshots.sort(key=lambda s: s.timestamp, reverse=True)
        return snapshots

    def diff(self, snapshot_id: Optional[str] = None) -> WorkspaceDiff:
        base_snap = self.get_snapshot(snapshot_id)
        if not base_snap:
            raise ValueError(f"Snapshot not found: {snapshot_id or 'latest'}")

        current_files = scan_workspace(self.workspace_root)
        base_files = base_snap.files

        added = []
        modified = []
        deleted = []
        unchanged = 0

        for rel, cur in current_files.items():
            if rel not in base_files:
                added.append(rel)
            elif base_files[rel]["sha256"] != cur.sha256:
                modified.append(rel)
            else:
                unchanged += 1

        for rel in base_files:
            if rel not in current_files:
                deleted.append(rel)

        return WorkspaceDiff(
            base_snapshot_id=base_snap.id,
            added=added,
            modified=modified,
            deleted=deleted,
            unchanged_count=unchanged,
            total_changed=len(added) + len(modified) + len(deleted),
        )

    def rollback(self, snapshot_id: Optional[str] = None) -> RollbackResult:
        start_time = time.time()
        base_snap = self.get_snapshot(snapshot_id)
        if not base_snap:
            return RollbackResult(
                success=False,
                snapshot_id=snapshot_id or "unknown",
                duration_ms=0,
                error=f"Snapshot not found: {snapshot_id or 'latest'}",
            )

        restored_files: List[str] = []
        deleted_files: List[str] = []
        reverted_files: List[str] = []

        try:
            current_files = scan_workspace(self.workspace_root)
            base_files = base_snap.files

            # 1. Delete files created after snapshot
            for rel, cur in current_files.items():
                if rel not in base_files:
                    if os.path.exists(cur.path):
                        os.remove(cur.path)
                        deleted_files.append(rel)

            # 2. Revert modified & restore deleted files
            for rel, base_f in base_files.items():
                cur = current_files.get(rel)
                target_path = os.path.join(self.workspace_root, rel)

                if cur is None:
                    # Deleted file: restore
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    content = self.object_store.get_file_content(base_f["sha256"])
                    with open(target_path, "wb") as f:
                        f.write(content)
                    restored_files.append(rel)
                elif cur.sha256 != base_f["sha256"]:
                    # Modified file: revert
                    content = self.object_store.get_file_content(base_f["sha256"])
                    with open(target_path, "wb") as f:
                        f.write(content)
                    reverted_files.append(rel)

            # 3. Clean empty directories
            self._cleanup_empty_dirs(self.workspace_root)

            duration_ms = (time.time() - start_time) * 1000.0
            return RollbackResult(
                success=True,
                snapshot_id=base_snap.id,
                restored_files=restored_files,
                deleted_files=deleted_files,
                reverted_files=reverted_files,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000.0
            return RollbackResult(
                success=False,
                snapshot_id=base_snap.id,
                restored_files=restored_files,
                deleted_files=deleted_files,
                reverted_files=reverted_files,
                duration_ms=duration_ms,
                error=str(e),
            )

    def commit(self, name: Optional[str] = None) -> Snapshot:
        return self.create_snapshot(name or "Committed changes")

    def _cleanup_empty_dirs(self, dir_path: str, is_root: bool = True) -> bool:
        if not os.path.exists(dir_path):
            return True

        is_empty = True
        for entry in os.listdir(dir_path):
            if entry in (".sandstorm", ".git"):
                is_empty = False
                continue
            full_path = os.path.join(dir_path, entry)
            if os.path.isdir(full_path):
                child_empty = self._cleanup_empty_dirs(full_path, False)
                if child_empty:
                    try:
                        os.rmdir(full_path)
                    except OSError:
                        is_empty = False
                else:
                    is_empty = False
            else:
                is_empty = False

        return not is_root and is_empty
