# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository-local sensitive path policy."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

_SENSITIVE_DIRECTORY_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".docker",
        ".gnupg",
        ".kube",
        ".ssh",
        "gcloud",
    }
)
_SENSITIVE_FILE_NAMES = frozenset(
    {
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "application_default_credentials.json",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "key.json",
        "kubeconfig",
    }
)
_SENSITIVE_FILE_SUFFIXES = (".jks", ".key", ".keystore", ".p12", ".pem", ".pfx")


def is_sensitive_repository_path(relative_path: str | PurePosixPath) -> bool:
    """Return whether a repository-relative path is protected by default."""
    normalized = str(relative_path).replace("\\", "/").casefold()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path = PurePosixPath(normalized)
    name = path.name
    parts = path.parts
    if name.startswith(".env"):
        return True
    if any(part in _SENSITIVE_DIRECTORY_NAMES for part in parts):
        return True
    if name in _SENSITIVE_FILE_NAMES or name.endswith(_SENSITIVE_FILE_SUFFIXES):
        return True
    return name.endswith(".json") and (
        name.startswith("service-account") or name.endswith("-credentials.json")
    )


def resolve_allowed_sensitive_files(
    source_root: str | Path,
    requested_paths: list[str] | tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Validate exact runtime opt-ins and return canonical repository-relative paths."""
    root = Path(source_root).resolve()
    resolved_paths: list[str] = []
    for requested_path in requested_paths:
        raw_path = str(requested_path).strip()
        if not raw_path:
            raise ValueError("--allow-sensitive-file requires a non-empty relative file path")
        path = Path(raw_path)
        if path.is_absolute():
            raise ValueError(f"Sensitive-file opt-in must be repository-relative: {raw_path}")
        if ".." in PurePosixPath(raw_path.replace("\\", "/")).parts:
            raise ValueError(f"Sensitive-file opt-in does not allow parent traversal: {raw_path}")
        if any(character in raw_path for character in "*?[]"):
            raise ValueError(f"Sensitive-file opt-in does not allow glob patterns: {raw_path}")

        candidate = root / path
        try:
            relative_parts = candidate.relative_to(root).parts
        except ValueError as error:
            raise ValueError(
                f"Sensitive-file opt-in is outside the repository: {raw_path}"
            ) from error
        current = root
        for part in relative_parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"Sensitive-file opt-in does not allow symlinks: {raw_path}")
        try:
            resolved_candidate = candidate.resolve(strict=True)
            relative_path = resolved_candidate.relative_to(root).as_posix()
        except (FileNotFoundError, ValueError) as error:
            raise ValueError(
                f"Sensitive-file opt-in must name an existing file inside the repository: {raw_path}"
            ) from error
        if not resolved_candidate.is_file():
            raise ValueError(f"Sensitive-file opt-in must name a regular file: {raw_path}")
        if not is_sensitive_repository_path(relative_path):
            raise ValueError(
                f"Sensitive-file opt-in is unnecessary for an unprotected path: {relative_path}"
            )
        if relative_path not in resolved_paths:
            resolved_paths.append(relative_path)
    return tuple(resolved_paths)
