"""
cli.py: Command line interface for agent_sandstorm (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import sys
import os
import argparse
from .sandbox import Sandstorm
from .cow import CoWSnapshotManager
from .audit import AuditLogger, export_timeline_ascii, generate_html_report


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="sandstorm-py",
        description="Zero-Trust Agent Execution Sandbox & Copy-on-Write Workspace Isolation Engine (Nymrel)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # run command
    run_parser = subparsers.add_parser("run", help="Run a command inside zero-trust sandbox")
    run_parser.add_argument("cmd", nargs="+", help="Command to run")
    run_parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace")
    run_parser.add_argument("--allow", action="append", help="Allowed domain (can be repeated)")
    run_parser.add_argument("--max-spend", type=float, default=None, help="Max spend USD")
    run_parser.add_argument("--no-rollback", action="store_true", help="Disable auto rollback on error")

    # snapshot command
    snap_parser = subparsers.add_parser("snapshot", help="Create CoW workspace snapshot")
    snap_parser.add_argument("name", nargs="?", default=None, help="Snapshot name")
    snap_parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace")

    # rollback command
    rb_parser = subparsers.add_parser("rollback", help="Restore workspace to snapshot")
    rb_parser.add_argument("snapshot_id", nargs="?", default=None, help="Snapshot ID")
    rb_parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace")

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Show workspace diff")
    diff_parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace")

    # commit command
    commit_parser = subparsers.add_parser("commit", help="Commit changes to new snapshot")
    commit_parser.add_argument("name", nargs="?", default=None, help="Commit snapshot name")
    commit_parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "run":
        cmd_str = " ".join(args.cmd)
        print(f"\n🛡️  SANDSTORM (PY): Executing '{cmd_str}' in {args.workspace}\n")
        sandbox = Sandstorm(
            workspace=args.workspace,
            allow_domains=args.allow,
            max_spend_usd=args.max_spend,
            auto_rollback_on_error=not args.no_rollback,
        )
        res = sandbox.run(lambda ctx: ctx.exec(cmd_str))
        if res.success:
            print(f"\n✅ Execution succeeded ({res.duration_ms:.1f}ms)")
        else:
            print(f"\n❌ Execution failed: {res.error}")
            if res.rollback_performed:
                print("🔄 Automatic CoW Rollback performed.")
        print("\n" + sandbox.get_timeline())
        return 0 if res.success else 1

    elif args.command == "snapshot":
        cow = CoWSnapshotManager(args.workspace)
        snap = cow.create_snapshot(args.name)
        print(f"\n📸 Snapshot created: {snap.id} ({snap.file_count} files, Merkle: {snap.tree_hash[:12]}...)\n")
        return 0

    elif args.command == "rollback":
        cow = CoWSnapshotManager(args.workspace)
        res = cow.rollback(args.snapshot_id)
        if res.success:
            print(f"\n🔄 Rollback complete: Restored {len(res.restored_files)}, Reverted {len(res.reverted_files)}, Deleted {len(res.deleted_files)}\n")
            return 0
        else:
            print(f"\n❌ Rollback failed: {res.error}\n")
            return 1

    elif args.command == "diff":
        cow = CoWSnapshotManager(args.workspace)
        diff = cow.diff()
        print(f"\n📊 Diff (Added: {len(diff.added)}, Modified: {len(diff.modified)}, Deleted: {len(diff.deleted)}, Unchanged: {diff.unchanged_count})\n")
        return 0

    elif args.command == "commit":
        cow = CoWSnapshotManager(args.workspace)
        snap = cow.commit(args.name)
        print(f"\n💾 Committed snapshot: {snap.id}\n")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
