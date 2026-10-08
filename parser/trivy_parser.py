"""
Converts Trivy's JSON output into ARGUS findings.
Trivy reports two kinds of problems:
  - Vulnerabilities in dependencies (category: "dependency")
  - Secrets found in files          (category: "secret")
"""

import json
import sys

from parser.common import make_finding

# Trivy already uses a scale close to ours
TRIVY_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "UNKNOWN",
}


def parse_trivy(path):
    """Read a Trivy JSON file and return a list of ARGUS findings."""
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    findings = []

    for result in data.get("Results", []):
        target = result.get("Target")

        # Trivy lists the line each package is on separately, under "Packages".
        # Build a lookup table: package name -> line number
        package_lines = {}
        for package in result.get("Packages") or []:
            locations = package.get("Locations") or []
            if locations:
                package_lines[package.get("Name")] = locations[0].get("StartLine")

        # 1. Dependency vulnerabilities
        for vuln in result.get("Vulnerabilities") or []:
            original = vuln.get("Severity", "UNKNOWN")
            package_name = vuln.get("PkgName")
            installed = vuln.get("InstalledVersion")
            fixed = vuln.get("FixedVersion")

            if fixed:
                fix = f"Upgrade {package_name} from {installed} to {fixed} or newer."
            else:
                fix = f"No fixed version of {package_name} is available yet."

            findings.append(make_finding(
                tool="trivy",
                category="dependency",
                rule_id=vuln.get("VulnerabilityID"),
                title=vuln.get("Title") or vuln.get("VulnerabilityID"),
                severity=TRIVY_SEVERITY_MAP.get(original, "UNKNOWN"),
                original_severity=original,
                file=target,
                line=package_lines.get(package_name),
                package=package_name,
                installed_version=installed,
                fixed_version=fixed,
                cwe=vuln.get("CweIDs") or [],
                description=vuln.get("Description", ""),
                fix=fix,
                references=vuln.get("References") or [],
                raw=vuln,
            ))

        # 2. Secrets
        for secret in result.get("Secrets") or []:
            original = secret.get("Severity", "UNKNOWN")
            findings.append(make_finding(
                tool="trivy",
                category="secret",
                rule_id=secret.get("RuleID"),
                title=secret.get("Title") or "Secret found in file",
                severity=TRIVY_SEVERITY_MAP.get(original, "UNKNOWN"),
                original_severity=original,
                file=target,
                line=secret.get("StartLine"),
                fix="Remove this secret from the code, revoke it, and create a new one.",
                raw=secret,
            ))

    return findings


# Lets you test this file on its own:  python -m parser.trivy_parser
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "scan-results/trivy.json"
    findings = parse_trivy(path)

    print(f"Parsed {len(findings)} findings from Trivy\n")
    for finding in findings:
        where = finding["package"] or finding["file"]
        print(f"[{finding['severity']:<8}] {finding['rule_id']:<22} {where:<10} -> {finding['fix']}")
        