"""Utilities for parsing and validating requirements files."""

from pathlib import Path


def resolve_manifest_path(target_path: str, manifest_path: str) -> Path:
    """
    Resolve manifest path relative to target_path.
    Validates that the result is within target_path (no path traversal).
    """
    target = Path(target_path).resolve()
    manifest = (target / manifest_path).resolve()
    if not str(manifest).startswith(str(target)):
        raise ValueError("manifest_path must resolve within target_path")
    return manifest


def validate_target_path(target_path: str) -> Path:
    """Validate target path exists and is a directory."""
    path = Path(target_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"target_path does not exist: {target_path}")
    if not path.is_dir():
        raise ValueError(f"target_path must be a directory: {target_path}")
    return path
