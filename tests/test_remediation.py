"""Remediation endpoint tests (mocked)."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.schemas.remediation import RemediationRecommendation


@pytest.fixture
def mock_recommendations() -> list[RemediationRecommendation]:
    """Sample remediation recommendations."""
    return [
        RemediationRecommendation(
            package="requests",
            current_version="2.25.0",
            recommended_version="2.31.0",
            vulnerability_ids=["CVE-2023-32681"],
            severity=None,
            kev_listed=False,
            rationale="Upgrade to 2.31.0 (lowest version fixing 1 vuln)",
            confidence="high",
            upgrade_type="minor",
            manual_review_required=False,
            fixed_versions=["2.31.0"],
        )
    ]


def test_remediate_returns_recommendations(
    client: TestClient, mock_recommendations: list[RemediationRecommendation]
) -> None:
    """Remediation endpoint returns structured recommendations."""
    with patch(
        "app.api.routes.remediation.run_remediation",
        return_value=mock_recommendations,
    ):
        resp = client.post(
            "/api/v1/remediate",
            json={"target_path": ".", "manifest_path": "requirements.txt"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["recommendation_count"] == 1
    assert len(data["recommendations"]) == 1
    rec = data["recommendations"][0]
    assert rec["package"] == "requests"
    assert rec["current_version"] == "2.25.0"
    assert rec["recommended_version"] == "2.31.0"
    assert rec["upgrade_type"] == "minor"
    assert "rationale" in rec


def test_remediate_returns_404_when_file_not_found(client: TestClient) -> None:
    """Remediation returns 404 when manifest not found."""
    with patch("app.api.routes.remediation.run_remediation") as mock:
        mock.side_effect = FileNotFoundError("manifest file not found")
        resp = client.post(
            "/api/v1/remediate",
            json={"target_path": "/nonexistent", "manifest_path": "requirements.txt"},
        )
    assert resp.status_code == 404
