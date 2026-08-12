# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared repository traversal policy for source analysis and snapshots."""

from __future__ import annotations

import os
from collections.abc import Iterator
from fnmatch import fnmatchcase
from pathlib import Path

from antares_cli.core.sensitive_paths import is_sensitive_repository_path

MAX_REPOSITORY_FILES = 100_000
MAX_REPOSITORY_BYTES = 2 * 1024 * 1024 * 1024
MAX_REPOSITORY_FILE_BYTES = 256 * 1024 * 1024

COMMON_IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".antares-data",
        ".git",
        ".gradle",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        ".worktrees",
        "__pycache__",
        "node_modules",
        "venv",
    }
)


def normalize_ignore_patterns(ignore_paths: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """Normalize repository-relative exclusion patterns."""
    return tuple(
        pattern.strip().removeprefix("./").rstrip("/")
        for pattern in ignore_paths
        if pattern.strip()
    )


def matches_ignore_pattern(relative_path: str, *, name: str, pattern: str) -> bool:
    """Return whether one repository path matches a normalized exclusion pattern."""
    if fnmatchcase(relative_path, pattern) or fnmatchcase(name, pattern):
        return True
    if pattern.endswith("/**"):
        directory_prefix = pattern.removesuffix("/**").rstrip("/")
        return relative_path == directory_prefix or relative_path.startswith(f"{directory_prefix}/")
    return False


def iter_repository_files(
    root: Path,
    *,
    ignore_paths: list[str] | tuple[str, ...] = (),
    allow_sensitive_files: tuple[str, ...] = (),
) -> Iterator[Path]:
    """Yield files deterministically without descending into ignored trees."""
    normalized_patterns = normalize_ignore_patterns(ignore_paths)
    if root.is_file():
        if not any(
            matches_ignore_pattern(root.name, name=root.name, pattern=pattern)
            for pattern in normalized_patterns
        ):
            yield root
        return
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in COMMON_IGNORED_DIRECTORY_NAMES
            and not any(
                matches_ignore_pattern(
                    (relative_directory / name).as_posix(),
                    name=name,
                    pattern=pattern,
                )
                for pattern in normalized_patterns
            )
        )
        directory_path = Path(directory)
        for file_name in sorted(file_names):
            path = directory_path / file_name
            relative_path = (relative_directory / file_name).as_posix()
            if (
                not path.is_symlink()
                and not any(
                    matches_ignore_pattern(relative_path, name=file_name, pattern=pattern)
                    for pattern in normalized_patterns
                )
                and (
                    not is_sensitive_repository_path(relative_path)
                    or relative_path in allow_sensitive_files
                )
            ):
                yield path
