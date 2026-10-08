"""
The full ARGUS pipeline:  scan -> normalize -> save.

Usage:  python -m app.pipeline <folder-to-scan>
"""

import sys
from collections import Counter
from pathlib import Path

from scanner.runner import run_all
from parser.all_parsers import parse_all
from database.db import init_db, save_scan


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m app.pipeline <folder-to-scan>")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.is_dir():
        print(f"Error: '{target}' is not a folder.")
        sys.exit(1)

    print(f"🛡️  ARGUS scanning {target}\n")

    print("Step 1/3 — Running scanners")
    results = run_all(target)
    succeeded = [name for name, ok in results.items() if ok]
    if not succeeded:
        print("\nAll scanners failed. Nothing to save.")
        sys.exit(1)

    print("\nStep 2/3 — Normalizing findings")
    findings = parse_all()
    print(f"  {len(findings)} findings in ARGUS format")

    print("\nStep 3/3 — Saving to database")
    init_db()
    scan_id = save_scan(str(target.resolve()), succeeded, findings)
    print(f"  Saved as scan #{scan_id}")

    print("\nSeverity summary:", dict(Counter(f["severity"] for f in findings)))


if __name__ == "__main__":
    main()
    