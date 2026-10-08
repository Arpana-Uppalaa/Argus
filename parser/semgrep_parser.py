"""
Converts Semgrep's JSON output into ARGUS findings.
Semgrep finds problems in your own code (category: "code").
"""

import json
import sys

from parser.common import make_finding

# Semgrep uses a different scale, so we translate it.
# This mapping is an ARGUS design decision (documented for the research write-up).
SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # Newer Semgrep versions may already use these words:
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def clean_cwe(cwe_text):
    """Turn 'CWE-78: Improper Neutralization...' into just 'CWE-78'."""
    return cwe_text.split(":")[0].strip()


def parse_semgrep(path):
    """Read a Semgrep JSON file and return a list of ARGUS findings."""
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    findings = []

    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        original = extra.get("severity", "UNKNOWN")

        # A short readable title: the vulnerability class if Semgrep gives one,
        # otherwise the last part of the rule name
        classes = metadata.get("vulnerability_class") or []
        title = classes[0] if classes else result.get("check_id", "").split(".")[-1]

        findings.append(make_finding(
            tool="semgrep",
            category="code",
            rule_id=result.get("check_id"),
            title=title,
            severity=SEMGREP_SEVERITY_MAP.get(original, "UNKNOWN"),
            original_severity=original,
            file=result.get("path"),
            line=result.get("start", {}).get("line"),
            cwe=[clean_cwe(c) for c in metadata.get("cwe") or []],
            description=extra.get("message", ""),
            fix=extra.get("fix") or "See the description and reference links for how to fix this code.",
            references=metadata.get("references") or [],
            raw=result,
        ))

    return findings


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "scan-results/semgrep.json"
    findings = parse_semgrep(path)

    print(f"Parsed {len(findings)} findings from Semgrep\n")
    for finding in findings:
        print(f"[{finding['severity']:<8}] line {finding['line']:<4} {finding['title']:<25} {finding['cwe']}")