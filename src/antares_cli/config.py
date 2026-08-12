# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Configuration loading for Antares CLI."""

from __future__ import annotations

import json
import os
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, get_origin

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from antares_cli.inference.defaults import (
    DEFAULT_ANTARES_CONTEXT_WINDOW,
    DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS,
)

_PROJECT_CONFIG_FIELDS = frozenset({"ignore_paths"})
_MAX_PROJECT_CONFIG_BYTES = 64 * 1024


class AntaresSettings(BaseSettings):
    """Validated runtime settings with manual precedence handling."""

    model_config = SettingsConfigDict(env_prefix="ANTARES_", extra="ignore")

    model: str = ""
    endpoint: str | None = None
    ignore_paths: list[str] = Field(default_factory=list)
    backend: str = "remote"
    context_window: int = DEFAULT_ANTARES_CONTEXT_WINDOW
    remote_timeout_seconds: float = DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS
    api_key: str | None = None

    @classmethod
    def discover_project_config(cls, start_path: Path | None = None) -> Path | None:
        candidate_path = (start_path or Path.cwd()).resolve()
        search_root = candidate_path if candidate_path.is_dir() else candidate_path.parent
        for directory in [search_root, *search_root.parents]:
            project_config_path = directory / ".antares.toml"
            try:
                project_config_path.lstat()
            except FileNotFoundError:
                continue
            else:
                return project_config_path
        return None

    @classmethod
    def load(
        cls,
        *,
        start_path: Path | None = None,
        cli_overrides: Mapping[str, Any] | None = None,
    ) -> AntaresSettings:
        merged_settings: dict[str, Any] = {}
        project_config_path = cls.discover_project_config(start_path)
        if project_config_path is not None:
            project_settings = _load_toml_file(project_config_path)
            merged_settings.update(
                {
                    key: value
                    for key, value in project_settings.items()
                    if key in _PROJECT_CONFIG_FIELDS
                }
            )

        merged_settings.update(_load_environment_settings())
        merged_settings.update(
            {
                key: value
                for key, value in (cli_overrides or {}).items()
                if value is not None and value != ""
            },
        )
        return cls.model_validate(merged_settings)


def _load_toml_file(path: Path) -> dict[str, Any]:
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    open_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, open_flags)
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise ValueError(
            f"Project configuration must be a regular, non-symlink file: {path}"
        ) from error
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Project configuration must be a regular, non-symlink file: {path}")
        if metadata.st_size > _MAX_PROJECT_CONFIG_BYTES:
            raise ValueError(
                f"Project configuration exceeds the {_MAX_PROJECT_CONFIG_BYTES:,}-byte limit: "
                f"{path}"
            )
        payload = bytearray()
        while len(payload) <= _MAX_PROJECT_CONFIG_BYTES:
            chunk = os.read(
                file_descriptor, min(8192, _MAX_PROJECT_CONFIG_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _MAX_PROJECT_CONFIG_BYTES:
            raise ValueError(
                f"Project configuration exceeds the {_MAX_PROJECT_CONFIG_BYTES:,}-byte limit: "
                f"{path}"
            )
    finally:
        os.close(file_descriptor)
    loaded = tomllib.loads(payload.decode("utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _load_environment_settings() -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for field_name in AntaresSettings.model_fields:
        environment_name = f"ANTARES_{field_name.upper()}"
        if environment_name not in os.environ:
            continue
        parsed[field_name] = _parse_environment_value(
            field_name=field_name,
            raw_value=os.environ[environment_name],
        )
    return parsed


def _parse_environment_value(*, field_name: str, raw_value: str) -> Any:
    field_info = AntaresSettings.model_fields[field_name]
    origin = get_origin(field_info.annotation)
    if origin is list:
        return _parse_list_value(raw_value)
    if field_info.annotation is int:
        return int(raw_value)
    if field_info.annotation is float:
        return float(raw_value)
    return raw_value


def _parse_list_value(raw_value: str) -> list[str]:
    normalized_value = raw_value.strip()
    if not normalized_value:
        return []
    if normalized_value.startswith("["):
        parsed = json.loads(normalized_value)
        if not isinstance(parsed, list):
            raise ValueError("Expected a JSON list for Antares configuration")
        return [str(item) for item in parsed]
    return [item.strip() for item in normalized_value.split(",") if item.strip()]


def resolve_data_root(*, start_path: Path | None = None) -> Path:
    environment_data_root = os.environ.get("ANTARES_DATA_DIR")
    if environment_data_root:
        return Path(environment_data_root)

    configured_data_root = Path.home() / ".local" / "share" / "antares-cli"
    if _has_writable_parent(configured_data_root):
        return configured_data_root

    fallback_root = (start_path or Path.cwd()).resolve() / ".antares-data"
    fallback_root.mkdir(parents=True, exist_ok=True)
    return fallback_root


def _has_writable_parent(candidate_path: Path) -> bool:
    current_path = candidate_path if candidate_path.exists() else candidate_path.parent
    while not current_path.exists() and current_path != current_path.parent:
        current_path = current_path.parent
    return os.access(current_path, os.W_OK)
