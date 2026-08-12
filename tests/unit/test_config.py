# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path

import pytest

from antares_cli.config import AntaresSettings


def test_default_runtime_settings_match_antares_deployments(
    monkeypatch,
    tmp_path: Path,
) -> None:
    for environment_name in (
        "ANTARES_CONTEXT_WINDOW",
        "ANTARES_REMOTE_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(environment_name, raising=False)

    settings = AntaresSettings.load(start_path=tmp_path)

    assert settings.context_window == 16_384
    assert settings.remote_timeout_seconds == 300.0


def test_settings_precedence(monkeypatch, tmp_path: Path) -> None:
    project_root = tmp_path / "repo"
    project_root.mkdir()
    (project_root / ".antares.toml").write_text(
        'model = "1B-dense"\ncontext_window = 4096\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTARES_MODEL", "1B-hybrid")

    settings = AntaresSettings.load(
        start_path=project_root,
        cli_overrides={"context_window": 16384},
    )

    assert settings.model == "1B-hybrid"
    assert settings.context_window == 16384


def test_project_config_cannot_allow_sensitive_files(tmp_path: Path) -> None:
    project_root = tmp_path / "repo"
    project_root.mkdir()
    (project_root / ".antares.toml").write_text(
        'allow_sensitive_files = [".env"]\n',
        encoding="utf-8",
    )

    settings = AntaresSettings.load(start_path=project_root)

    assert not hasattr(settings, "allow_sensitive_files")


def test_project_config_must_not_be_a_symlink(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_text('ignore_paths = ["secret"]\n', encoding="utf-8")
    (repository / ".antares.toml").symlink_to(outside)

    with pytest.raises(ValueError, match="regular, non-symlink file"):
        AntaresSettings.load(start_path=repository)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported on this platform")
def test_project_config_must_be_a_regular_file(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    os.mkfifo(repository / ".antares.toml")

    with pytest.raises(ValueError, match="regular, non-symlink file"):
        AntaresSettings.load(start_path=repository)


def test_project_config_has_a_small_size_limit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".antares.toml").write_bytes(b"#" * (64 * 1024 + 1))

    with pytest.raises(ValueError, match="65,536-byte limit"):
        AntaresSettings.load(start_path=repository)
