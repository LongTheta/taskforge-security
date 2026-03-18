"""Path validation for scan requests - prevents traversal and abuse."""

from pathlib import Path

# Max path length to prevent abuse (e.g. path exhaustion)
MAX_PATH_LENGTH = 4096


def validate_target_path(target_path: str) -> Path:
    """Validate target path exists, is a directory, and within length limits."""
    if len(target_path) > MAX_PATH_LENGTH:
        raise ValueError("target_path exceeds maximum allowed length")
    path = Path(target_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"target_path does not exist: {target_path}")
    if not path.is_dir():
        raise ValueError(f"target_path must be a directory: {target_path}")
    return path


def resolve_manifest_path(target_path: str, manifest_path: str) -> Path:
    """
    Resolve manifest path relative to target_path.
    Validates: within target_path (no traversal), path length limits.
    """
    if len(manifest_path) > MAX_PATH_LENGTH:
        raise ValueError("manifest_path exceeds maximum allowed length")
    target = Path(target_path).resolve()
    manifest = (target / manifest_path).resolve()
    if not str(manifest).startswith(str(target)):
        raise ValueError("manifest_path must resolve within target_path")
    return manifest
