"""Remediation endpoint tests."""

from fastapi.testclient import TestClient


def test_remediate_returns_recommendations(client: TestClient) -> None:
    """Remediation endpoint returns version recommendations."""
    resp = client.post(
        "/api/v1/remediate",
        json={
            "vulnerabilities": [
                {
                    "package": "requests",
                    "current_version": "2.25.0",
                    "vulnerability_id": "CVE-2023-32681",
                    "fixed_versions": ["2.31.0", "2.28.0"],
                }
            ]
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "recommendations" in data
    recs = data["recommendations"]
    assert len(recs) == 1
    assert recs[0]["package"] == "requests"
    assert recs[0]["current_version"] == "2.25.0"
    assert recs[0]["recommended_version"] == "2.28.0"  # lowest fixed
    assert recs[0]["confidence"] == "high"


def test_remediate_handles_no_fix_versions(client: TestClient) -> None:
    """Remediation handles vulnerabilities with no fix versions."""
    resp = client.post(
        "/api/v1/remediate",
        json={
            "vulnerabilities": [
                {
                    "package": "legacy-pkg",
                    "current_version": "1.0.0",
                    "vulnerability_id": "CVE-2020-1234",
                    "fixed_versions": [],
                }
            ]
        },
    )
    assert resp.status_code == 200
    recs = resp.json()["recommendations"]
    assert len(recs) == 1
    assert recs[0]["recommended_version"] == "unknown"
    assert recs[0]["confidence"] == "low"
