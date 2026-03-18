"""OSV enrichment tests - graceful failure when unavailable."""

from unittest.mock import patch

import httpx

from app.scanners.osv import enrich_with_osv
from app.schemas.scan import VulnerabilityItem


def test_osv_enrichment_returns_original_when_http_fails() -> None:
    """When OSV API fails, return original items unchanged."""
    items = [
        VulnerabilityItem(
            package="requests",
            current_version="2.25.0",
            vulnerability_id="CVE-2023-32681",
            summary="Test",
            fixed_versions=["2.31.0"],
            source="pip-audit",
        )
    ]
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.post.side_effect = httpx.HTTPError("Network error")
        result = enrich_with_osv(items, api_base="https://api.osv.dev", timeout=5)
    assert len(result) == 1
    assert result[0].package == "requests"
    assert result[0].osv_enriched is False


def test_osv_enrichment_empty_list() -> None:
    """Empty input returns empty output."""
    assert enrich_with_osv([], api_base="https://api.osv.dev", timeout=5) == []
