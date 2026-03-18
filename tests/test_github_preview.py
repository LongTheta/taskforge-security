"""GitHub PR preview tests."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.schemas.remediation import RemediationRecommendation


@pytest.fixture
def mock_recommendations() -> list[RemediationRecommendation]:
    """Sample recommendations for PR preview."""
    return [
        RemediationRecommendation(
            package="requests",
            current_version="2.25.0",
            recommended_version="2.31.0",
            vulnerability_ids=["CVE-2023-32681"],
            rationale="Upgrade",
            confidence="high",
            upgrade_type="minor",
            manual_review_required=False,
        )
    ]


def test_preview_pr_returns_payload(
    client: TestClient, mock_recommendations: list[RemediationRecommendation]
) -> None:
    """Preview PR endpoint returns payload without calling GitHub."""
    with patch(
        "app.api.routes.remediation.run_remediation",
        return_value=mock_recommendations,
    ):
        resp = client.get(
            "/api/v1/remediate/preview-pr",
            params={"target_path": ".", "manifest_path": "requirements.txt"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "payload" in data
    assert "branch_name" in data["payload"]
    assert "pr_title" in data["payload"]
    assert "pr_body" in data["payload"]
    assert data["recommendation_count"] == 1
