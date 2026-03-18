"""Trivy container image scanner - runs trivy CLI and parses JSON output."""

import json
import re
import shutil
import subprocess

from app.core.logging_config import get_logger
from app.schemas.scan import VulnerabilityItem

logger = get_logger(__name__)

# Sanitize image ref: alphanumeric, colon, slash, hyphen, underscore, dot
IMAGE_REF_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9/.:_-]{0,255}$")


def trivy_available() -> bool:
    """Check if trivy CLI is installed."""
    return shutil.which("trivy") is not None


def run_trivy_image(image_ref: str, timeout: int = 120) -> list[VulnerabilityItem]:
    """
    Run trivy image scan and parse JSON output.
    Requires trivy CLI to be installed. Returns normalized VulnerabilityItem list.
    """
    if not trivy_available():
        raise RuntimeError("trivy CLI not found. Install from https://trivy.dev")

    if not IMAGE_REF_PATTERN.match(image_ref):
        raise ValueError("Invalid image reference")

    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--quiet",
        image_ref,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("trivy image scan timed out") from None
    except FileNotFoundError:
        raise RuntimeError("trivy CLI not found") from None

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"trivy failed (exit {result.returncode}): {result.stderr or result.stdout}"
        )

    return _parse_trivy_json(result.stdout, image_ref)


def _parse_trivy_json(stdout: str, image_ref: str) -> list[VulnerabilityItem]:
    """Parse trivy JSON output into VulnerabilityItem list."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise ValueError(f"trivy produced invalid JSON: {e}") from e

    items: list[VulnerabilityItem] = []
    results = data.get("Results", [])

    for res in results:
        target = res.get("Target", image_ref)
        vulns = res.get("Vulnerabilities", []) or []
        for v in vulns:
            vuln_id = v.get("VulnerabilityID", "UNKNOWN")
            pkg = v.get("PkgName", "unknown")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            fixed_versions = [fixed] if fixed else []
            severity = (v.get("Severity") or "").lower()
            title = v.get("Title", "")
            desc = v.get("Description", "")
            summary = title or desc or "No description"

            items.append(
                VulnerabilityItem(
                    package=pkg,
                    current_version=installed,
                    vulnerability_id=vuln_id,
                    summary=summary,
                    fixed_versions=fixed_versions,
                    source="trivy",
                    severity=severity if severity in ("critical", "high", "medium", "low") else None,
                )
            )

    return items
