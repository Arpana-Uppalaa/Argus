"""
The common ARGUS finding format.

Every scanner's output is converted into this same shape,
so the rest of ARGUS only needs to understand one format.
"""

# The ARGUS severity scale, from most to least serious
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def make_finding(tool, category, rule_id, title, severity, original_severity,
                 file=None, line=None, package=None, installed_version=None,
                 fixed_version=None, cwe=None, description="", fix="",
                 references=None, raw=None):
    """Build one finding in the ARGUS format."""

    # Safety check: refuse severities that aren't on our scale
    if severity not in SEVERITY_LEVELS:
        raise ValueError(f"Unknown severity '{severity}' from {tool}")

    return {
        "tool": tool,
        "category": category,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "original_severity": original_severity,
        "file": file,
        "line": line,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "cwe": cwe or [],
        "description": description,
        "fix": fix,
        "references": references or [],
        "raw": raw,  # the original scanner data, untouched
    }