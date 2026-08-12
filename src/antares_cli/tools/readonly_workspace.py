# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Disposable, immutable repository snapshots for model-driven exploration."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import weakref
from collections.abc import Callable
from itertools import chain
from pathlib import Path
from types import TracebackType

from antares_cli.core.repository_paths import (
    COMMON_IGNORED_DIRECTORY_NAMES,
    MAX_REPOSITORY_BYTES,
    MAX_REPOSITORY_FILE_BYTES,
    MAX_REPOSITORY_FILES,
    matches_ignore_pattern,
    normalize_ignore_patterns,
)
from antares_cli.core.sensitive_paths import (
    is_sensitive_repository_path,
    resolve_allowed_sensitive_files,
)


class ReadOnlyRepositorySnapshot:
    """Own a point-in-time repository copy with every write bit removed."""

    def __init__(
        self,
        source_root: str | Path,
        *,
        ignore_paths: list[str] | tuple[str, ...] = (),
        allow_sensitive_files: list[str] | tuple[str, ...] = (),
    ) -> None:
        self.source_root = Path(source_root).resolve()
        if not self.source_root.is_dir():
            raise ValueError(f"Repository target must be a directory: {self.source_root}")
        self.allowed_sensitive_files = resolve_allowed_sensitive_files(
            self.source_root,
            allow_sensitive_files,
        )

        temporary_root = Path(tempfile.mkdtemp(prefix="antares-readonly-"))
        self.root = temporary_root / "repository"
        try:
            shutil.copytree(
                self.source_root,
                self.root,
                symlinks=True,
                ignore=_snapshot_ignore(
                    self.source_root,
                    ignore_paths,
                    self.allowed_sensitive_files,
                ),
            )
            _sanitize_snapshot_symlinks(self.source_root, self.root)
            _remove_write_permissions(self.root)
        except Exception:
            _remove_snapshot(temporary_root)
            raise
        self._finalizer = weakref.finalize(self, _remove_snapshot, temporary_root)

    def close(self) -> None:
        self._finalizer()

    def __enter__(self) -> ReadOnlyRepositorySnapshot:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


def _snapshot_ignore(
    source_root: Path,
    ignore_paths: list[str] | tuple[str, ...],
    allowed_sensitive_files: tuple[str, ...],
) -> Callable[[str, list[str]], set[str]]:
    normalized_patterns = normalize_ignore_patterns(ignore_paths)
    copied_file_count = 0
    copied_bytes = 0

    def ignore(directory: str, names: list[str]) -> set[str]:
        nonlocal copied_bytes, copied_file_count
        relative_directory = Path(directory).resolve().relative_to(source_root)
        ignored: set[str] = set()
        for name in names:
            candidate = Path(directory) / name
            relative_path = (relative_directory / name).as_posix()
            if (
                candidate.is_dir()
                and not candidate.is_symlink()
                and name in COMMON_IGNORED_DIRECTORY_NAMES
            ):
                ignored.add(name)
                continue
            if any(
                matches_ignore_pattern(relative_path, name=name, pattern=pattern)
                for pattern in normalized_patterns
            ):
                ignored.add(name)
                continue
            if (
                is_sensitive_repository_path(relative_path)
                and relative_path not in allowed_sensitive_files
            ):
                ignored.add(name)
                continue
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                file_size = candidate.stat().st_size
            except FileNotFoundError:
                ignored.add(name)
                continue
            if file_size > MAX_REPOSITORY_FILE_BYTES:
                raise ValueError(
                    f"Repository file exceeds the {MAX_REPOSITORY_FILE_BYTES:,}-byte snapshot "
                    f"limit: {relative_path}. Add it to ignore_paths if it is not source code."
                )
            copied_file_count += 1
            copied_bytes += file_size
            if copied_file_count > MAX_REPOSITORY_FILES or copied_bytes > MAX_REPOSITORY_BYTES:
                raise ValueError(
                    "Repository exceeds the read-only snapshot budget "
                    f"({MAX_REPOSITORY_FILES:,} files / {MAX_REPOSITORY_BYTES:,} bytes). "
                    "Exclude dependency, build, or generated trees with ignore_paths."
                )
        return ignored

    return ignore


def _remove_write_permissions(root: Path) -> None:
    for entry in chain((root,), root.rglob("*")):
        if entry.is_symlink():
            continue
        mode = stat.S_IMODE(entry.stat().st_mode)
        entry.chmod(mode & ~0o222)


def _sanitize_snapshot_symlinks(source_root: Path, snapshot_root: Path) -> None:
    for directory, directory_names, file_names in os.walk(snapshot_root, followlinks=False):
        directory_path = Path(directory)
        for name in [*directory_names, *file_names]:
            snapshot_path = directory_path / name
            if not snapshot_path.is_symlink():
                continue
            relative_path = snapshot_path.relative_to(snapshot_root)
            source_path = source_root / relative_path
            try:
                resolved_source = source_path.resolve(strict=True)
                resolved_source.relative_to(source_root)
            except (FileNotFoundError, ValueError):
                snapshot_path.unlink()
                continue

            snapshot_target = snapshot_root / resolved_source.relative_to(source_root)
            if not snapshot_target.exists():
                snapshot_path.unlink()
                continue
            relative_target = os.path.relpath(snapshot_target, start=snapshot_path.parent)
            snapshot_path.unlink()
            snapshot_path.symlink_to(relative_target, target_is_directory=resolved_source.is_dir())


def _remove_snapshot(temporary_root: Path) -> None:
    if not temporary_root.exists():
        return
    for directory, directory_names, file_names in os.walk(
        temporary_root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_path.chmod(0o700)
        for name in [*directory_names, *file_names]:
            path = directory_path / name
            if path.is_symlink():
                continue
            try:
                path.chmod(0o700 if path.is_dir() else 0o600)
            except FileNotFoundError:
                continue
    shutil.rmtree(temporary_root)
