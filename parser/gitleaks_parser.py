"""
Converts Gitleaks' JSON output into ARGUS findings.
Gitleaks finds secrets (category: "secret").
"""

import json
import sys

from parser.common import make_finding

# Gitleaks gives NO severity. ARGUS rates every leaked secret HIGH by default:
# a working credential gives an attacker direct access, with no exploit needed.
# (Design decision, documented for the research write-up.)
GITLEAKS_DEFAULT_SEVERITY = "HIGH"


def parse_gitleaks(path):
    """Read a Gitleaks JSON file and return a list of ARGUS findings."""
    with open(path, encoding="utf-8") as file:
        data = json.load(file) or []   # an empty report may be null

    findings = []

    for leak in data:
        # Security: never store a secret, even if --redact was forgotten.
        # This is the ONE deliberate exception to "never discard data".
        safe_raw = dict(leak)
        safe_raw["Secret"] = "REDACTED"
        safe_raw["Match"] = "REDACTED"

        findings.append(make_finding(
            tool="gitleaks",
            category="secret",
            rule_id=leak.get("RuleID"),
            title=leak.get("Description") or "Secret found in file",
            severity=GITLEAKS_DEFAULT_SEVERITY,
            original_severity="NONE",
            file=leak.get("File"),
            line=leak.get("StartLine"),
            fix="Remove this secret from the code, revoke it, and create a new one.",
            raw=safe_raw,
        ))

    return findings


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "scan-results/gitleaks.json"
    findings = parse_gitleaks(path)

    print(f"Parsed {len(findings)} findings from Gitleaks\n")
    for finding in findings:
        print(f"[{finding['severity']:<8}] {finding['rule_id']:<25} {finding['file']}:{finding['line']}")
        