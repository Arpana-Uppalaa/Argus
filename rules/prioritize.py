"""
Context-aware prioritization: severity + context -> priority score + reasons.
"""

import sys

from parser.all_parsers import parse_all, severity_rank
from parser.common import SEVERITY_LEVELS
from rules.context import collect_context, import_name, resolve_path

# ALL scoring weights in one place, so they can be tuned and evaluated later.
# These are starting hypotheses, not proven values.
WEIGHTS = {
    "severity": {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20,
                 "LOW": 10, "INFO": 5, "UNKNOWN": 15},
    "secret": 25,
    "web_exposed": 20,
    "package_imported": 15,
    "package_not_imported": -10,
    "high_confidence": 5,
    "low_confidence": -10,
    "confirmed_by_other_tool": 10,
    "fix_available": 5,
}

# Score -> priority band
BANDS = [
    (70, "P1", "Fix now"),
    (50, "P2", "Fix soon"),
    (30, "P3", "Plan to fix"),
    (-999, "P4", "Backlog"),
]


def band_for(score):
    for minimum, band, label in BANDS:
        if score >= minimum:
            return band, label


def location_key(finding, target):
    """Identify a finding's exact spot (file + line), to spot duplicates."""
    if not finding["file"] or not finding["line"]:
        return None
    return (resolve_path(finding["file"], target), finding["line"])


def enclosing_route(finding, context, target):
    """If the finding sits inside a web route function, return the route."""
    if not finding["file"] or not finding["line"]:
        return None
    path = resolve_path(finding["file"], target)
    for start, end, route in context["routes"].get(path, []):
        if start <= finding["line"] <= end:
            return route
    return None


def score_finding(finding, context, tools_at_location, target):
    """Return (score, list of reasons) for one finding."""
    W = WEIGHTS
    factors = []   # list of (points, plain-English reason)

    severity = finding["severity"]
    factors.append((W["severity"][severity], f"{severity.title()} severity"))

    if finding["category"] == "secret":
        factors.append((W["secret"],
                        "Leaked credential: gives direct access, no hacking needed"))

    if finding["category"] == "dependency" and finding["package"]:
        name = import_name(finding["package"])
        if name in context["imported"]:
            factors.append((W["package_imported"],
                            f"Your code imports '{name}' directly"))
        else:
            factors.append((W["package_not_imported"],
                            f"Your code doesn't import '{name}' directly "
                            "(another library may still use it)"))
        if finding["fixed_version"]:
            factors.append((W["fix_available"],
                            f"Easy fix: upgrade to {finding['fixed_version']}"))

    if finding["category"] == "code":
        route = enclosing_route(finding, context, target)
        if route:
            factors.append((W["web_exposed"],
                            f"Inside web route {route}: any visitor can trigger it"))
        raw = finding["raw"] or {}
        confidence = raw.get("extra", {}).get("metadata", {}).get("confidence")
        if confidence == "HIGH":
            factors.append((W["high_confidence"], "Scanner is highly confident"))
        elif confidence == "LOW":
            factors.append((W["low_confidence"],
                            "Scanner has low confidence (possible false positive)"))

    key = location_key(finding, target)
    if key and len(tools_at_location.get(key, set())) > 1:
        others = sorted(tools_at_location[key] - {finding["tool"]})
        if others:
            factors.append((W["confirmed_by_other_tool"],
                            f"Also reported by {', '.join(others)}"))

    score = sum(points for points, _ in factors)
    reasons = [f"{points:+d}  {text}" for points, text in factors]
    return score, reasons


def ranking_order(finding):
    """Highest score first; ties broken by severity."""
    return (-finding["priority_score"], SEVERITY_LEVELS.index(finding["severity"]))


def prioritize(findings, target):
    """Add priority_score, priority_band, priority_label and reasons to each
    finding, and return them sorted with the most urgent first."""
    context = collect_context(target)

    # Which tools reported something at each file + line?
    tools_at_location = {}
    for finding in findings:
        key = location_key(finding, target)
        if key:
            tools_at_location.setdefault(key, set()).add(finding["tool"])

    for finding in findings:
        score, reasons = score_finding(finding, context, tools_at_location, target)
        finding["priority_score"] = score
        finding["priority_band"], finding["priority_label"] = band_for(score)
        finding["reasons"] = reasons

    return sorted(findings, key=ranking_order)


# Compare against the severity-only baseline:  python -m rules.prioritize
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../argus-test-target"
    findings = parse_all()

    # 1. Baseline: severity only
    for rank, finding in enumerate(sorted(findings, key=severity_rank), start=1):
        finding["baseline_rank"] = rank

    # 2. ARGUS: severity + context
    ranked = prioritize(findings, target)

    print(f"ARGUS priority list ({len(ranked)} findings)\n")
    for rank, f in enumerate(ranked[:10], start=1):
        move = f["baseline_rank"] - rank
        arrow = f"▲{move}" if move > 0 else (f"▼{-move}" if move < 0 else "=")
        where = f"{f['file'].split('/')[-1]}:{f['line']}" if f["line"] else f["file"]
        print(f"#{rank:<3} {f['priority_band']} {f['priority_label']:<11} "
              f"score {f['priority_score']:<3} (severity-only rank: "
              f"#{f['baseline_rank']} {arrow})")
        print(f"     {f['tool']}: {f['title'][:60]}  [{where}]")
        for reason in f["reasons"]:
            print(f"        {reason}")
        print()

    print("Bands:", {band: sum(1 for f in ranked if f["priority_band"] == band)
                     for band in ["P1", "P2", "P3", "P4"]})
                     