"""KEV prioritization tests."""

from unittest.mock import patch

import pytest

from app.scanners.kev import apply_kev_flags, clear_kev_cache, is_kev_listed
from app.schemas.scan import VulnerabilityItem


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear KEV cache before each test."""
    clear_kev_cache()
    yield
    clear_kev_cache()


def test_apply_kev_flags_when_kev_empty() -> None:
    """When KEV catalog is empty, kev_listed stays False."""
    with patch("app.scanners.kev._load_kev_catalog", return_value=set()):
        items = [
            VulnerabilityItem(
                package="foo",
                current_version="1.0",
                vulnerability_id="CVE-2024-1234",
                summary="Test",
                fixed_versions=[],
            )
        ]
        result = apply_kev_flags(items)
    assert result[0].kev_listed is False


def test_apply_kev_flags_when_kev_listed() -> None:
    """When CVE is in KEV catalog, kev_listed is True."""
    with patch(
        "app.scanners.kev._load_kev_catalog",
        return_value={"CVE-2024-1234"},
    ):
        items = [
            VulnerabilityItem(
                package="foo",
                current_version="1.0",
                vulnerability_id="CVE-2024-1234",
                summary="Test",
                fixed_versions=[],
            )
        ]
        result = apply_kev_flags(items)
    assert result[0].kev_listed is True


def test_is_kev_listed() -> None:
    """is_kev_listed checks CVE ID and aliases."""
    with patch(
        "app.scanners.kev._load_kev_catalog",
        return_value={"CVE-2024-9999"},
    ):
        assert is_kev_listed("CVE-2024-9999") is True
        assert is_kev_listed("CVE-2024-0000") is False
        assert is_kev_listed("other-id", aliases=["CVE-2024-9999"]) is True
