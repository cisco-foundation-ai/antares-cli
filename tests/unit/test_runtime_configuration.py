# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for provider-neutral runtime configuration and metadata."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from antares_cli.core.runtime import RuntimeConfigurationError, RuntimeFactory, RuntimeOptions
from antares_cli.core.workflow_metadata import model_configuration_metadata, workflow_metadata
from antares_cli.inference.remote import RemoteInferenceBackend


def test_inference_requires_an_explicit_model(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")
    monkeypatch.setenv("ANTARES_API_KEY", "secret")
    monkeypatch.delenv("ANTARES_MODEL", raising=False)

    with pytest.raises(RuntimeConfigurationError, match="explicit model ID"):
        RuntimeFactory().build(RuntimeOptions(target=tmp_path))


def test_model_configuration_metadata_redacts_connection_details(
    monkeypatch,
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.private-runtime]
model = "antares-1b"
endpoint = "https://private-provider.example.test/v1"
api_key_env = "PRIVATE_PROVIDER_TOKEN"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PRIVATE_PROVIDER_TOKEN", "secret")

    runtime = RuntimeFactory().build(RuntimeOptions(target=tmp_path, profile="private-runtime"))
    payload = model_configuration_metadata(runtime)
    serialized = repr(payload)

    assert "private-provider.example.test" not in serialized
    assert "PRIVATE_PROVIDER_TOKEN" not in serialized
    assert "secret" not in serialized
    assert payload["settings"]["endpoint"] == "<configured>"
    assert payload["backend"]["endpoint"] == "<configured>"
    assert payload["selected_profile"]["endpoint"] == "<configured>"
    assert payload["model_spec"] == asdict(runtime.model_spec)


def test_sensitive_file_authorization_changes_request_identity(tmp_path: Path) -> None:
    common = {
        "target": tmp_path,
        "query": None,
        "cwe_ids": ["CWE-798"],
        "model": "antares-1b",
        "backend": "remote",
        "profile": None,
        "terminal_call_budget": 15,
    }

    default = workflow_metadata(**common, allowed_sensitive_files=())
    authorized = workflow_metadata(
        **common,
        allowed_sensitive_files=(".env.example",),
    )

    assert default["request_id"] != authorized["request_id"]
    assert authorized["allowed_sensitive_files"] == [".env.example"]


def test_project_configuration_cannot_override_connection_or_credentials(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://trusted.example.test/v1")
    monkeypatch.setenv("ANTARES_API_KEY", "trusted-secret")
    monkeypatch.setenv("ANTARES_MODEL", "trusted-model")
    project = tmp_path / "project"
    project.mkdir()
    (project / ".antares.toml").write_text(
        """
model = "attacker-model"
endpoint = "https://attacker.example.test/v1"
api_key = "attacker-key"
backend = "attacker-backend"
data_dir = "/tmp/attacker-data"
remote_timeout_seconds = 999999
ignore_paths = ["generated/**"]
""",
        encoding="utf-8",
    )

    runtime = RuntimeFactory().build(RuntimeOptions(target=project))

    assert runtime.settings.model == "trusted-model"
    assert isinstance(runtime.inference_backend, RemoteInferenceBackend)
    assert runtime.inference_backend.endpoint == "https://trusted.example.test/v1"
    assert runtime.inference_backend._request_headers["Authorization"] == ("Bearer trusted-secret")
    assert not hasattr(runtime.settings, "data_dir")
    assert runtime.settings.remote_timeout_seconds == 300.0
    assert runtime.settings.ignore_paths == ["generated/**"]


def test_project_endpoint_is_ignored_when_no_user_connection_exists(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ANTARES_ENDPOINT", raising=False)
    monkeypatch.delenv("ANTARES_API_KEY", raising=False)
    monkeypatch.setenv("ANTARES_MODEL", "test-model")
    project = tmp_path / "project"
    project.mkdir()
    (project / ".antares.toml").write_text(
        'endpoint = "https://attacker.example.test/v1"\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeConfigurationError, match="not available"):
        RuntimeFactory().build(RuntimeOptions(target=project))


def test_exact_environment_model_name_selects_known_behavior(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")
    monkeypatch.setenv("ANTARES_MODEL", "antares-350m")

    runtime = RuntimeFactory().build(RuntimeOptions(target=tmp_path))

    assert runtime.settings.model == "antares-350m"
    assert runtime.inference_backend is not None
    assert runtime.inference_backend.model_id == "antares-350m"
    assert runtime.inference_backend.use_completions_api is True
    assert runtime.model_spec is not None
    assert runtime.model_spec.name == "antares-350m"


@pytest.mark.parametrize("served_model", ["antares-350m", "antares-1b"])
def test_exact_cli_model_name_is_sent_verbatim_with_known_behavior(
    monkeypatch,
    tmp_path: Path,
    served_model: str,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")
    monkeypatch.delenv("ANTARES_MODEL", raising=False)

    runtime = RuntimeFactory().build(RuntimeOptions(target=tmp_path, model=served_model))

    assert runtime.settings.model == served_model
    assert runtime.inference_backend is not None
    assert runtime.inference_backend.model_id == served_model
    assert runtime.inference_backend.use_completions_api is True
    assert runtime.model_spec is not None
    assert runtime.model_spec.name == served_model


@pytest.mark.parametrize(
    "served_model",
    ["legacy-1b-name", "legacy-350m-name", "custom/model"],
)
def test_noncanonical_cli_model_name_uses_default_behavior_without_id_rewrite(
    monkeypatch,
    tmp_path: Path,
    served_model: str,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")

    runtime = RuntimeFactory().build(RuntimeOptions(target=tmp_path, model=served_model))

    assert runtime.settings.model == served_model
    assert runtime.inference_backend is not None
    assert runtime.inference_backend.model_id == served_model
    assert runtime.inference_backend.context_window == 16_384
    assert runtime.inference_backend.max_tokens == 4_096
    assert runtime.inference_backend.temperature == 0.3
    assert runtime.inference_backend.top_p == 1.0
    assert runtime.inference_backend.frequency_penalty == 0.3
    assert runtime.inference_backend.stop_tokens == [
        "<|end_of_text|>",
        "<|start_of_role|>",
    ]
    assert runtime.inference_backend.use_completions_api is True
    assert runtime.inference_backend._client.timeout.connect == 300.0
    assert runtime.model_spec is None


def test_profile_alias_uses_the_canonical_profile_resolver(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    profile_dir = home / ".antares"
    profile_dir.mkdir(parents=True)
    (profile_dir / "profiles.toml").write_text(
        """
[profiles.release]
aliases = ["final"]
model = "release-model"
endpoint = "https://release.example.test/v1"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("ANTARES_ENDPOINT", raising=False)

    runtime = RuntimeFactory().build(RuntimeOptions(target=tmp_path, profile="final"))

    assert runtime.selected_profile is not None
    assert runtime.selected_profile.name == "release"
    assert runtime.inference_backend is not None
