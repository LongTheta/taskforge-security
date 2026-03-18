"""Policy gate endpoint tests."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.schemas.scan import RiskSummary, ScanResponse, VulnerabilityItem


@pytest.fixture
def scan_pass() -> ScanResponse:
    """Scan with no blocking findings."""
    return ScanResponse(
        vulnerability_count=0,
        vulnerabilities=[],
        risk_summary=RiskSummary(critical_count=0, high_count=0, medium_count=0, low_count=0, kev_count=0),
        osv_enrichment_available=False,
        kev_prioritization_available=False,
    )


@pytest.fixture
def scan_block_critical() -> ScanResponse:
    """Scan with critical finding."""
    return ScanResponse(
        vulnerability_count=1,
        vulnerabilities=[
            VulnerabilityItem(
                package="openssl",
                current_version="1.0",
                vulnerability_id="CVE-2024-0001",
                summary="Critical",
                fixed_versions=["2.0"],
                source="trivy",
                severity="critical",
                priority="critical",
            )
        ],
        risk_summary=RiskSummary(critical_count=1, high_count=0, medium_count=0, low_count=0, kev_count=0),
        osv_enrichment_available=False,
        kev_prioritization_available=False,
    )


@pytest.fixture
def scan_block_kev() -> ScanResponse:
    """Scan with KEV-listed finding."""
    return ScanResponse(
        vulnerability_count=1,
        vulnerabilities=[
            VulnerabilityItem(
                package="lib",
                current_version="1.0",
                vulnerability_id="CVE-2024-0002",
                summary="KEV",
                fixed_versions=[],
                source="pip-audit",
                kev_listed=True,
                priority="critical",
            )
        ],
        risk_summary=RiskSummary(critical_count=1, high_count=0, medium_count=0, low_count=0, kev_count=1),
        osv_enrichment_available=False,
        kev_prioritization_available=True,
    )


def test_gate_passes_when_no_blocking_findings(client: TestClient, scan_pass: ScanResponse) -> None:
    """Gate returns pass when no critical or KEV findings."""
    with patch("app.api.routes.gate.run_scan", return_value=scan_pass):
        resp = client.get("/api/v1/gate?target_path=.&manifest_path=requirements.txt")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pass"] is True
    assert data["blocked_by"] == []
    assert data["vulnerability_count"] == 0


def test_gate_blocks_on_critical(client: TestClient, scan_block_critical: ScanResponse) -> None:
    """Gate returns fail when critical findings exist (policy_block_critical=true)."""
    with patch("app.api.routes.gate.run_scan", return_value=scan_block_critical):
        resp = client.get("/api/v1/gate?target_path=.&manifest_path=requirements.txt")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pass"] is False
    assert "critical" in str(data["blocked_by"]).lower()
    assert data["vulnerability_count"] == 1


def test_gate_blocks_on_kev(client: TestClient, scan_block_kev: ScanResponse) -> None:
    """Gate returns fail when KEV findings exist (policy_block_kev=true)."""
    with patch("app.api.routes.gate.run_scan", return_value=scan_block_kev):
        resp = client.get("/api/v1/gate?target_path=.&manifest_path=requirements.txt")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pass"] is False
    assert "kev" in str(data["blocked_by"]).lower()
