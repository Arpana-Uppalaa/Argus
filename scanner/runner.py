"""
ARGUS scanner runner.

Runs Trivy, Semgrep and Gitleaks against a target folder
and saves each tool's raw JSON output into scan-results/.
"""

import shutil
import subprocess
import sys
from pathlib import Path

OUTPUT_DIR = Path("scan-results")


def tool_installed(tool_name):
    """Return True if the tool can be found on this computer."""
    return shutil.which(tool_name) is not None


def run_scanner(name, command, output_file, ok_exit_codes):
    """Run one scanner and report whether it produced its output file."""
    if not tool_installed(command[0]):
        print(f"  ✗ {name} is not installed. Skipping.")
        return False

    # Delete old results first, so we never mistake a stale file for a new one
    if output_file.exists():
        output_file.unlink()

    print(f"→ Running {name}...")
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode not in ok_exit_codes or not output_file.exists():
        print(f"  ✗ {name} failed (exit code {result.returncode})")
        print(result.stderr[-500:])
        return False

    print(f"  ✓ {name} finished → {output_file}")
    return True


def run_all(target):
    """Run all three scanners on a folder. Returns {tool name: True/False}."""
    target = Path(target)
    OUTPUT_DIR.mkdir(exist_ok=True)

    trivy_out = OUTPUT_DIR / "trivy.json"
    semgrep_out = OUTPUT_DIR / "semgrep.json"
    gitleaks_out = OUTPUT_DIR / "gitleaks.json"

    return {
        "Trivy": run_scanner(
            "Trivy",
            ["trivy", "fs", "--format", "json",
             "--output", str(trivy_out), str(target)],
            trivy_out,
            ok_exit_codes={0},
        ),
        "Semgrep": run_scanner(
            "Semgrep",
            ["semgrep", "scan", "--config", "p/python", "--metrics=off",
             "--json", "--output", str(semgrep_out), str(target)],
            semgrep_out,
            ok_exit_codes={0},
        ),
        "Gitleaks": run_scanner(
            "Gitleaks",
            ["gitleaks", "dir", str(target), "--redact",
             "--report-format", "json", "--report-path", str(gitleaks_out)],
            gitleaks_out,
            ok_exit_codes={0, 1},  # 1 just means "leaks were found"
        ),
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scanner.runner <folder-to-scan>")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.is_dir():
        print(f"Error: '{target}' is not a folder.")
        sys.exit(1)

    print(f"ARGUS scanning: {target}\n")
    results = run_all(target)

    print("\nSummary:")
    for name, ok in results.items():
        print(f"  {'✓' if ok else '✗'} {name}")


if __name__ == "__main__":
    main()