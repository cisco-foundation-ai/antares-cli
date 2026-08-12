# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for user-defined inference profiles."""

from __future__ import annotations

import pytest

from antares_cli.inference.profiles import (
    MODEL_CATALOG,
    EndpointSpec,
    GenerationSpec,
    InferenceProfile,
    ProfileConfigurationError,
    load_profiles,
    resolve_model_spec,
    resolve_profile,
)


def test_builtin_catalog_contains_only_current_canonical_model_ids() -> None:
    assert set(MODEL_CATALOG) == {"antares-350m", "antares-1b"}
    assert "antares-1b" in MODEL_CATALOG
    model_spec = MODEL_CATALOG["antares-1b"]
    assert model_spec.adapter == "antares"
    assert model_spec.generation.use_completions_api is True
    assert not hasattr(model_spec, "endpoint")
    assert not hasattr(model_spec, "api_key")


def test_default_generation_spec_matches_antares_deployment_contract() -> None:
    generation = GenerationSpec()

    assert generation.max_tokens == 4_096
    assert generation.temperature == 0.3
    assert generation.top_p == 1.0
    assert generation.repetition_penalty is None
    assert generation.frequency_penalty == 0.3
    assert generation.stop_tokens == ["<|end_of_text|>", "<|start_of_role|>"]
    assert generation.use_completions_api is True


def test_resolve_model_spec_requires_an_exact_behavior_name() -> None:
    expected = MODEL_CATALOG["antares-1b"]

    assert resolve_model_spec("antares-1b") == expected
    assert resolve_model_spec("short-name") is None
    assert resolve_model_spec("legacy-model-name") is None
    assert resolve_model_spec("legacy-1b-name") is None
    assert resolve_model_spec("legacy-350m-name") is None


def test_resolve_profile_returns_none_for_unknown() -> None:
    assert resolve_profile("nonexistent-model") is None


def test_load_profiles_returns_no_connections_without_runtime_configuration(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/tmp/nonexistent-home")
    monkeypatch.delenv("ANTARES_ENDPOINT", raising=False)

    assert load_profiles() == []


def test_endpoint_spec_resolves_api_key_from_named_environment(monkeypatch) -> None:
    monkeypatch.setenv("QWEN_API_KEY", "qwen-key")
    endpoint = EndpointSpec(api_key_env="QWEN_API_KEY")

    assert endpoint.resolved_api_key == "qwen-key"


def test_endpoint_spec_resolves_url_from_named_environment(monkeypatch) -> None:
    monkeypatch.setenv("INFERENCE_ENDPOINT", "https://inference.example.test/v1")
    endpoint = EndpointSpec(url_env="INFERENCE_ENDPOINT")

    assert endpoint.resolved_url == "https://inference.example.test/v1"


def test_load_profiles_exposes_generic_environment_connection(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")
    monkeypatch.setenv("ANTARES_MODEL", "antares-1b")

    profiles = load_profiles()

    assert len(profiles) == 1
    assert profiles[0].name == "environment"
    assert profiles[0].endpoint == "https://inference.example.test/v1"
    assert profiles[0].model_id == "antares-1b"
    assert profiles[0].generation.use_completions_api is True


def test_environment_connection_requires_an_explicit_model(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTARES_ENDPOINT", "https://inference.example.test/v1")
    monkeypatch.setenv("ANTARES_MODEL", "   ")

    assert load_profiles() == []


def test_load_profiles_supports_qwen_style_user_profile(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.qwen-coder]
display_name = "Qwen Coder"
backend = "remote"
provider = "openai_compatible"
endpoint = "https://qwen.example.test/v1"
model = "Qwen/Qwen2.5-Coder-32B-Instruct"
adapter = "antares"
api_key_env = "QWEN_API_KEY"
context_window = 131072
recommended_use_cases = ["General code audit"]
aliases = ["qwen"]

[profiles.qwen-coder.generation]
max_tokens = 8192
temperature = 0.1
top_p = 0.95
frequency_penalty = 0.0
stop_tokens = []
use_completions_api = false

""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    profile = next(profile for profile in load_profiles() if profile.name == "qwen-coder")

    assert profile.model_id == "Qwen/Qwen2.5-Coder-32B-Instruct"
    assert profile.adapter == "antares"
    assert profile.endpoint == "https://qwen.example.test/v1"
    assert profile.endpoint_spec is not None
    assert profile.endpoint_spec.api_key_env == "QWEN_API_KEY"
    assert profile.generation.max_tokens == 8192
    assert profile.generation.temperature == 0.1
    assert profile.generation.top_p == 0.95
    assert profile.generation.frequency_penalty == 0.0
    assert profile.generation.stop_tokens == []
    assert profile.generation.use_completions_api is False
    assert resolve_profile("qwen") is not None


def test_unknown_exact_model_id_inherits_default_antares_behavior(
    monkeypatch,
    tmp_path,
) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.hosted-antares]
model = "provider/antares-release-candidate"
endpoint = "https://inference.example.test/v1/completions"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    profile = resolve_profile("hosted-antares")

    assert profile is not None
    assert profile.model_id == "provider/antares-release-candidate"
    assert profile.context_window == 16_384
    assert profile.generation == GenerationSpec()


def test_user_profile_inherits_known_model_behavior(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.hosted-antares]
model = "antares-1b"
endpoint_env = "INFERENCE_ENDPOINT"
api_key_env = "INFERENCE_API_KEY"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("INFERENCE_ENDPOINT", "https://inference.example.test/v1")

    profile = resolve_profile("hosted-antares")

    assert profile is not None
    assert profile.model_id == "antares-1b"
    assert profile.endpoint == "https://inference.example.test/v1"
    assert profile.context_window == 16_384
    assert profile.generation.use_completions_api is True


def test_load_profiles_loads_any_backend(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.custom-backend]
backend = "custom"
model = "custom-model"
endpoint = "https://custom.test/v1"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    assert any(profile.name == "custom-backend" for profile in load_profiles())


def test_load_profiles_maps_max_new_tokens_alias(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.custom]
backend = "remote"
endpoint = "https://example.test/v1"
model = "custom-model"
max_new_tokens = 1234
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    profiles = {profile.name: profile for profile in load_profiles()}

    assert profiles["custom"].generation.max_tokens == 1234


def test_profile_rejects_output_reservation_without_prompt_capacity(
    monkeypatch,
    tmp_path,
) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        """
[profiles.invalid-capacity]
backend = "remote"
endpoint = "https://example.test/v1"
model = "custom-model"
context_window = 1024
max_tokens = 1023
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(ProfileConfigurationError, match="invalid-capacity"):
        load_profiles()


def test_programmatic_profile_enforces_prompt_capacity() -> None:
    with pytest.raises(ValueError, match="serialized prompt"):
        InferenceProfile(
            name="invalid-capacity",
            display_name="Invalid",
            model_id="custom-model",
            backend="remote",
            description="",
            context_window=1_024,
            generation=GenerationSpec(max_tokens=1_023),
        )


def test_profile_display_property() -> None:
    profile = InferenceProfile(
        name="test-profile",
        display_name="Test",
        model_id="provider/model-v2",
        backend="remote",
        endpoint="https://my-endpoint.test/v1",
        description="Test profile",
    )
    assert "provider/model-v2" in profile.display
    assert "my-endpoint.test" in profile.display


def test_profile_endpoint_display_removes_credentials_and_query_parameters() -> None:
    profile = InferenceProfile(
        name="private",
        display_name="Private",
        model_id="model",
        backend="remote",
        endpoint="https://user:secret@example.test/v1?token=secret#fragment",
        description="",
    )

    assert profile.endpoint_display == "https://example.test/…"
    assert "secret" not in profile.endpoint_display
    assert "/v1" not in profile.endpoint_display
    assert "secret" not in profile.display


@pytest.mark.parametrize(
    "invalid_profile",
    [
        'aliases = "prod"',
        'recommended_use_cases = "Audit"',
        '[profiles.invalid.generation]\nuse_completions_api = "false"',
        'generation = "invalid"',
        'endpoint_spec = "invalid"',
        "context_window = inf",
    ],
)
def test_invalid_profile_field_types_raise_contextual_configuration_error(
    tmp_path,
    monkeypatch,
    invalid_profile: str,
) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text(
        "[profiles.invalid]\n" + invalid_profile + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(ValueError, match="Invalid inference profile 'invalid'"):
        load_profiles()
