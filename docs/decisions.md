# ARGUS Design Decisions

## 1. Plain language first
Findings are explained so any developer can act on them, not just security experts.

## 2. Never discard data
The simplified view is for display; the original scanner output is always stored (`raw`).
Exception: secret values are never stored, even if a scanner includes them.

## 3. Severity mapping
- Semgrep: ERROR → HIGH, WARNING → MEDIUM, INFO → LOW
- Gitleaks gives no severity; ARGUS rates leaked secrets HIGH
  (a working credential gives direct access, no exploit needed)

## 4. Prioritization weights are hypotheses
All weights live in `rules/prioritize.py` (`WEIGHTS`) and will be evaluated
against the severity-only baseline.

## 5. Public website access levels (Phase 9)
- Repo owners (verified via GitHub login): full results
- Anyone else, public repos only: summary counts only, plus an option to notify the owner
- Reason: keep "scan any repo" useful to owners without handing attackers exact leak locations