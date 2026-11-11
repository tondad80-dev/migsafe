"""Command line entry point for migsafe."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .rules import SEVERITY_ORDER, check_files, to_text


def collect(paths: list[str]) -> dict[str, str]:
    """Read every .sql file given a path or directory."""
    files: dict[str, str] = {}
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*.sql")):
                files[str(child)] = child.read_text(encoding="utf-8", errors="replace")
        elif path.exists():
            files[str(path)] = path.read_text(encoding="utf-8", errors="replace")
        else:
            print(f"migsafe: no such path: {raw}", file=sys.stderr)
            raise SystemExit(2)
    if not files:
        print("migsafe: no .sql files found", file=sys.stderr)
        raise SystemExit(2)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="migsafe",
        description="Flag PostgreSQL migrations that lock tables or destroy data.",
    )
    parser.add_argument("paths", nargs="+", help="SQL files or directories")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--assume-transactional",
        action="store_true",
        help="assume each file starts inside a migration runner transaction",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high", "critical"],
        default="high",
        help="exit 2 when a finding at this severity or worse exists (default: high)",
    )
    parser.add_argument("--version", action="version", version=f"migsafe {__version__}")
    # `migsafe check path` reads better than a bare path list; accept both.
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "check":
        argv = argv[1:]
    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    report = check_files(collect(args.paths), assume_transactional=args.assume_transactional)

    if args.json:
        print(json.dumps({
            "files": report.files,
            "statements": report.statements,
            "worst": report.worst,
            "counts": report.counts(),
            "findings": [f.as_dict() for f in report.findings],
        }, indent=2))
    else:
        print(to_text(report))

    if args.fail_on != "none" and report.findings:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in report.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
