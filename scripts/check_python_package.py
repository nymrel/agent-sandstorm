"""Validate Python distribution contents without uploading them."""

from __future__ import annotations

import pathlib
import sys
import tarfile
import zipfile


distribution_dir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "python-dist")
wheels = sorted(distribution_dir.glob("*.whl"))
source_archives = sorted(distribution_dir.glob("*.tar.gz"))

if len(wheels) != 1 or len(source_archives) != 1:
    raise SystemExit("Expected exactly one wheel and one source archive")

with zipfile.ZipFile(wheels[0]) as wheel:
    names = set(wheel.namelist())

for name in names:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"Wheel contains an unsafe path: {name}")

required_suffixes = {
    "agent_sandstorm/__init__.py",
    "agent_sandstorm/cli.py",
    "agent_sandstorm/sandbox.py",
}
for required in required_suffixes:
    if required not in names:
        raise SystemExit(f"Wheel is missing required module: {required}")

if any(name.startswith("tests/") or "/tests/" in name for name in names):
    raise SystemExit("Wheel unexpectedly contains the repository test suite")

with tarfile.open(source_archives[0], "r:gz") as source_archive:
    members = source_archive.getmembers()

source_names = {member.name for member in members}
roots = {pathlib.PurePosixPath(name).parts[0] for name in source_names if name}
if len(roots) != 1:
    raise SystemExit("Source archive must contain exactly one top-level directory")
source_root = next(iter(roots))

for member in members:
    path = pathlib.PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
        raise SystemExit(f"Source archive contains an unsafe member: {member.name}")
    if any(part in {".git", ".sandstorm", "__pycache__", "build", "dist"} for part in path.parts):
        raise SystemExit(f"Source archive contains generated or private state: {member.name}")
    if member.name.endswith((".pyc", ".pyo")):
        raise SystemExit(f"Source archive contains bytecode: {member.name}")

for required in {
    f"{source_root}/LICENSE",
    f"{source_root}/README.md",
    f"{source_root}/pyproject.toml",
    f"{source_root}/python/agent_sandstorm/__init__.py",
    f"{source_root}/python/tests/test_e2e.py",
}:
    if required not in source_names:
        raise SystemExit(f"Source archive is missing required file: {required}")

print(
    f"Python package contract verified ({len(names)} wheel entries, "
    f"{len(members)} source entries)."
)
