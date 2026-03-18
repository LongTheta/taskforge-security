"""pip-audit scanner - runs pip-audit subprocess and parses JSON output."""

import json
import subprocess
from pathlib import Path

from app.schemas.scan import VulnerabilityItem


def run_pip_audit(manifest_path: Path, timeout: int) -> list[VulnerabilityItem]:
    """
    Run pip-audit against a requirements file and parse JSON output.
    Uses subprocess.run (NOT shell=True). Handles returncode 0 or 1 (both valid).
    """
    cmd = [
        "python",
        "-m",
        "pip_audit",
        "-r",
        str(manifest_path),
        "--format",
        "json",
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(manifest_path.parent),
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"pip-audit failed (exit {result.returncode}): {result.stderr or result.stdout}"
        )
    return _parse_pip_audit_json(result.stdout)


def _parse_pip_audit_json(stdout: str) -> list[VulnerabilityItem]:
    """Parse pip-audit JSON output into VulnerabilityItem list."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise ValueError(f"pip-audit produced invalid JSON: {e}") from e

    deps = data.get("dependencies", [])
    items: list[VulnerabilityItem] = []

    for dep in deps:
        if "skip_reason" in dep:
            continue
        name = dep.get("name", "")
        version = dep.get("version", "")
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            fix_versions = vuln.get("fix_versions", [])
            if isinstance(fix_versions, list):
                fix_versions = [str(v) for v in fix_versions]
            else:
                fix_versions = [str(fix_versions)] if fix_versions else []
            summary = vuln.get("description", vuln.get("summary", "")) or "No description"
            items.append(
                VulnerabilityItem(
                    package=name,
                    current_version=version,
                    vulnerability_id=vuln_id,
                    summary=summary,
                    fixed_versions=fix_versions,
                )
            )
    return items
