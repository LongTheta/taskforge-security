"""Prometheus metrics for TaskForge Security."""

from prometheus_client import Counter, Histogram, generate_latest

# Scan metrics
scan_total = Counter(
    "taskforge_security_scans_total",
    "Total number of scans",
    ["scan_type"],  # manifest, image
)
scan_vulnerabilities_total = Counter(
    "taskforge_security_scan_vulnerabilities_total",
    "Total vulnerabilities found across scans",
)
scan_duration_seconds = Histogram(
    "taskforge_security_scan_duration_seconds",
    "Scan duration in seconds",
    ["scan_type"],
    buckets=(1, 5, 10, 30, 60, 120),
)

# Gate metrics
gate_checks_total = Counter(
    "taskforge_security_gate_checks_total",
    "Total gate checks",
)
gate_failures_total = Counter(
    "taskforge_security_gate_failures_total",
    "Gate failures (blocked deployments)",
    ["reason"],  # critical, kev
)

# Remediation metrics
remediation_requests_total = Counter(
    "taskforge_security_remediation_requests_total",
    "Total remediation requests",
)
pr_creations_total = Counter(
    "taskforge_security_pr_creations_total",
    "PRs created",
)


def get_metrics() -> bytes:
    """Return Prometheus exposition format."""
    return generate_latest()
