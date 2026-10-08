"""
Runs every ARGUS parser and combines the results into one list.
"""

from collections import Counter
from pathlib import Path

from parser.common import SEVERITY_LEVELS
from parser.trivy_parser import parse_trivy
from parser.semgrep_parser import parse_semgrep
from parser.gitleaks_parser import parse_gitleaks

# Which parser handles which scanner output file
PARSERS = {
    "trivy.json": parse_trivy,
    "semgrep.json": parse_semgrep,
    "gitleaks.json": parse_gitleaks,
}


def parse_all(results_dir="scan-results"):
    """Parse every scanner output that exists and return one combined list."""
    findings = []
    for filename, parse in PARSERS.items():
        path = Path(results_dir) / filename
        if not path.exists():
            print(f"  ! {filename} not found, skipping")
            continue
        findings.extend(parse(path))
    return findings


def severity_rank(finding):
    """CRITICAL -> 0, HIGH -> 1, ... so sorting puts the worst first."""
    return SEVERITY_LEVELS.index(finding["severity"])


if __name__ == "__main__":
    findings = sorted(parse_all(), key=severity_rank)

    print(f"ARGUS found {len(findings)} findings\n")
    print("By tool:     ", dict(Counter(f["tool"] for f in findings)))
    print("By category: ", dict(Counter(f["category"] for f in findings)))
    print("By severity: ", dict(Counter(f["severity"] for f in findings)))
    print()

    for f in findings:
        where = Path(f["file"]).name if f["file"] else "?"
        if f["line"]:
            where += f":{f['line']}"
        print(f"[{f['severity']:<8}] {f['tool']:<8} {f['title'][:45]:<45} {where}")