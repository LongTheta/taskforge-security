"""Scan endpoint tests (mocked)."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.schemas.scan import ScanResponse, VulnerabilityItem


@pytest.fixture
def mock_scan_result() -> ScanResponse:
    """Sample scan result for mocking."""
    return ScanResponse(
        vulnerability_count=1,
        vulnerabilities=[
            VulnerabilityItem(
                package="requests",
                current_version="2.25.0",
                vulnerability_id="CVE-2023-32681",
                summary="Request smuggling",
                fixed_versions=["2.31.0"],
            )
        ],
    )


def test_scan_returns_vulnerabilities_when_success(
    client: TestClient, mock_scan_result: ScanResponse
) -> None:
    """Scan endpoint returns normalized vulnerabilities when scan succeeds."""
    with patch("app.api.routes.scan.run_scan", return_value=mock_scan_result):
        resp = client.post(
            "/api/v1/scan",
            json={"target_path": ".", "manifest_path": "requirements.txt"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["vulnerability_count"] == 1
    assert len(data["vulnerabilities"]) == 1
    vuln = data["vulnerabilities"][0]
    assert vuln["package"] == "requests"
    assert vuln["current_version"] == "2.25.0"
    assert vuln["vulnerability_id"] == "CVE-2023-32681"
    assert vuln["summary"] == "Request smuggling"
    assert vuln["fixed_versions"] == ["2.31.0"]


def test_scan_returns_404_when_file_not_found(client: TestClient) -> None:
    """Scan returns 404 when target or manifest does not exist."""
    with patch("app.api.routes.scan.run_scan") as mock:
        mock.side_effect = FileNotFoundError("manifest file not found: requirements.txt")
        resp = client.post(
            "/api/v1/scan",
            json={"target_path": "/nonexistent", "manifest_path": "requirements.txt"},
        )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_scan_returns_400_on_validation_error(client: TestClient) -> None:
    """Scan returns 400 on path traversal or validation error."""
    with patch("app.api.routes.scan.run_scan") as mock:
        mock.side_effect = ValueError("manifest_path must resolve within target_path")
        resp = client.post(
            "/api/v1/scan",
            json={"target_path": ".", "manifest_path": "../../../etc/passwd"},
        )
    assert resp.status_code == 400
