# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Provider-neutral model catalog and user-owned connection profiles.

The built-in catalog describes how Antares models behave, but deliberately has
no endpoint or credential fields. Connections are supplied at runtime through
generic environment variables or ``~/.antares/profiles.toml``.
"""

from __future__ import annotations

import math
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from antares_cli.inference.defaults import (
    DEFAULT_ANTARES_CONTEXT_WINDOW,
    DEFAULT_ANTARES_FREQUENCY_PENALTY,
    DEFAULT_ANTARES_MAX_TOKENS,
    DEFAULT_ANTARES_STOP_TOKENS,
    DEFAULT_ANTARES_TEMPERATURE,
    DEFAULT_ANTARES_TOP_P,
    DEFAULT_ANTARES_USE_COMPLETIONS_API,
)
from antares_cli.inference.granite import prompt_token_budget


class ProfileConfigurationError(ValueError):
    """A user profile file could not be parsed into valid connection profiles."""


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    url: str | None = None
    url_env: str | None = None
    api_key: str | None = None
    api_key_env: str | None = None
    timeout_seconds: float | None = None
    retry_count: int | None = None
    retry_delay: float | None = None

    @property
    def resolved_url(self) -> str | None:
        if self.url:
            return self.url
        if self.url_env:
            return os.environ.get(self.url_env)
        return None

    @property
    def resolved_api_key(self) -> str | None:
        if self.api_key:
            return self.api_key
        if self.api_key_env:
            return os.environ.get(self.api_key_env)
        return None


@dataclass(frozen=True, slots=True)
class GenerationSpec:
    max_tokens: int = DEFAULT_ANTARES_MAX_TOKENS
    temperature: float | None = DEFAULT_ANTARES_TEMPERATURE
    top_p: float | None = DEFAULT_ANTARES_TOP_P
    repetition_penalty: float | None = None
    frequency_penalty: float | None = DEFAULT_ANTARES_FREQUENCY_PENALTY
    stop_tokens: list[str] | None = field(default_factory=lambda: list(DEFAULT_ANTARES_STOP_TOKENS))
    use_completions_api: bool = DEFAULT_ANTARES_USE_COMPLETIONS_API


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """Endpoint-free behavior contract for a model family."""

    name: str
    display_name: str
    description: str
    context_window: int
    adapter: str = "antares"
    generation: GenerationSpec = field(default_factory=GenerationSpec)
    recommended_use_cases: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class InferenceProfile:
    name: str
    display_name: str
    model_id: str
    backend: str
    description: str
    endpoint: str | None = None
    api_key: str | None = None
    context_window: int = DEFAULT_ANTARES_CONTEXT_WINDOW
    recommended_use_cases: list[str] = field(default_factory=list)
    adapter: str = "antares"
    endpoint_spec: EndpointSpec | None = None
    generation: GenerationSpec = field(default_factory=GenerationSpec)
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        prompt_token_budget(
            context_window=self.context_window,
            reserved_output_tokens=self.generation.max_tokens,
        )
        endpoint_spec = self.endpoint_spec
        if endpoint_spec is None:
            endpoint_spec = EndpointSpec(
                url=self.endpoint,
                api_key=self.api_key,
                api_key_env=_default_api_key_env(self.backend),
            )
            object.__setattr__(self, "endpoint_spec", endpoint_spec)
        if self.endpoint is None and endpoint_spec.resolved_url is not None:
            object.__setattr__(self, "endpoint", endpoint_spec.resolved_url)
        if self.api_key is None and endpoint_spec.api_key is not None:
            object.__setattr__(self, "api_key", endpoint_spec.api_key)

    @property
    def display(self) -> str:
        return f"{self.name} ({self.model_id} · {self.endpoint_display})"

    @property
    def endpoint_display(self) -> str:
        """Return an endpoint safe for terminal display."""
        if not self.endpoint:
            return "not configured"
        try:
            parsed = urlsplit(self.endpoint)
            netloc = parsed.netloc.rsplit("@", maxsplit=1)[-1]
            if not parsed.scheme or not netloc:
                return "<configured>"
            display_path = "/…" if parsed.path and parsed.path != "/" else ""
            return urlunsplit((parsed.scheme, netloc, display_path, "", ""))
        except ValueError:
            return "<configured>"


def _antares_model_spec(
    model_id: str,
    display_name: str,
    description: str,
    recommended_use_cases: list[str],
) -> ModelSpec:
    return ModelSpec(
        name=model_id,
        display_name=display_name,
        adapter="antares",
        description=description,
        context_window=DEFAULT_ANTARES_CONTEXT_WINDOW,
        generation=GenerationSpec(),
        recommended_use_cases=recommended_use_cases,
    )


MODEL_CATALOG: dict[str, ModelSpec] = {
    "antares-1b": _antares_model_spec(
        "antares-1b",
        "Antares 1B",
        "Antares 1B model for file-level vulnerability localization",
        ["General code audit", "CI pipelines", "Deep scan"],
    ),
    "antares-350m": _antares_model_spec(
        "antares-350m",
        "Antares 350M",
        "Antares 350M model for file-level vulnerability localization",
        ["General code audit", "CI pipelines", "Quick scan"],
    ),
}


def resolve_model_spec(name: str) -> ModelSpec | None:
    """Resolve an endpoint-free model specification."""
    return MODEL_CATALOG.get(name)


def resolve_profile(name_or_alias: str) -> InferenceProfile | None:
    """Resolve a runtime connection profile by name or alias."""
    for profile in load_profiles():
        if name_or_alias == profile.name or name_or_alias in profile.aliases:
            return profile
    return None


def load_profiles() -> list[InferenceProfile]:
    """Return runtime connections configured outside the public package."""
    profiles = _load_user_profiles()
    environment_profile = _environment_profile()
    if environment_profile is not None and environment_profile.name not in {
        profile.name for profile in profiles
    }:
        profiles.append(environment_profile)
    return profiles


def _environment_profile() -> InferenceProfile | None:
    endpoint = os.environ.get("ANTARES_ENDPOINT")
    if endpoint is None or not endpoint.strip():
        return None
    requested_model = os.environ.get("ANTARES_MODEL", "").strip()
    if not requested_model:
        return None
    return _profile_from_entry(
        "environment",
        {
            "display_name": "Environment configuration",
            "model": requested_model,
            "backend": "remote",
            "endpoint": endpoint.strip(),
            "api_key_env": "ANTARES_API_KEY",
            "description": "Connection configured through Antares environment variables",
        },
    )


def _load_user_profiles() -> list[InferenceProfile]:
    """Load additional profiles from ~/.antares/profiles.toml."""
    config_path = Path.home() / ".antares" / "profiles.toml"
    if not config_path.exists():
        return []

    try:
        with open(config_path, "rb") as file:
            data = tomllib.load(file)
    except tomllib.TOMLDecodeError as error:
        raise ProfileConfigurationError(
            f"Invalid inference profile configuration in {config_path}: {error}"
        ) from None
    except (OSError, UnicodeError) as error:
        raise ProfileConfigurationError(
            f"Could not read inference profile configuration at {config_path} "
            f"({type(error).__name__})."
        ) from None

    raw_profiles = data.get("profiles", {})
    if not isinstance(raw_profiles, dict):
        raise ProfileConfigurationError(
            f"Invalid inference profile configuration in {config_path}: "
            "'profiles' must be a TOML table."
        )
    profiles: list[InferenceProfile] = []
    for name, raw_entry in raw_profiles.items():
        if not isinstance(raw_entry, dict):
            raise ProfileConfigurationError(
                f"Invalid inference profile '{name}' in {config_path}: "
                "profile must be a TOML table."
            )
        try:
            profiles.append(_profile_from_entry(name, raw_entry))
        except (TypeError, ValueError, OverflowError) as error:
            raise ProfileConfigurationError(
                f"Invalid inference profile '{name}' in {config_path} ({type(error).__name__})."
            ) from None
    return profiles


def _profile_from_entry(name: str, raw_entry: dict[str, Any]) -> InferenceProfile:
    entry: dict[str, Any] = raw_entry
    backend = _required_str(entry.get("backend", "remote"), field_name="backend")
    endpoint = _endpoint_spec_from_entry(entry)
    requested_model = _required_str(
        entry.get("model", entry.get("model_id")),
        field_name="model",
    ).strip()
    if not requested_model:
        raise ValueError("model must not be empty")
    model_spec = resolve_model_spec(requested_model)
    context_window = _positive_int(
        entry.get(
            "context_window",
            model_spec.context_window if model_spec is not None else DEFAULT_ANTARES_CONTEXT_WINDOW,
        ),
        field_name="context_window",
    )
    generation = _generation_spec_from_entry(
        entry,
        default=model_spec.generation if model_spec is not None else GenerationSpec(),
    )
    return InferenceProfile(
        name=name,
        display_name=_required_str(
            entry.get("display_name", model_spec.display_name if model_spec is not None else name),
            field_name="display_name",
        ),
        model_id=requested_model,
        backend=backend,
        endpoint_spec=endpoint,
        adapter=_adapter_from_entry(
            entry,
            default=model_spec.adapter if model_spec is not None else "antares",
        ),
        description=_required_str(
            entry.get("description", model_spec.description if model_spec is not None else ""),
            field_name="description",
        ),
        context_window=context_window,
        generation=generation,
        recommended_use_cases=_required_str_list(
            entry.get(
                "recommended_use_cases",
                model_spec.recommended_use_cases if model_spec is not None else [],
            ),
            field_name="recommended_use_cases",
        ),
        aliases=tuple(_required_str_list(entry.get("aliases", []), field_name="aliases")),
    )


def _endpoint_spec_from_entry(entry: dict[str, Any]) -> EndpointSpec:
    endpoint_entry = entry.get("endpoint_spec", {})
    if not isinstance(endpoint_entry, dict):
        raise TypeError("endpoint_spec must be a TOML table")
    endpoint_url = entry.get("endpoint", endpoint_entry.get("url"))
    return EndpointSpec(
        url=_optional_str(endpoint_url),
        url_env=_optional_str(entry.get("endpoint_env", endpoint_entry.get("url_env"))),
        api_key=_optional_str(entry.get("api_key")),
        api_key_env=_required_str(
            entry.get("api_key_env", endpoint_entry.get("api_key_env", "ANTARES_API_KEY")),
            field_name="api_key_env",
        ),
        timeout_seconds=_optional_float(
            entry.get("remote_timeout_seconds", endpoint_entry.get("timeout_seconds"))
        ),
        retry_count=_optional_int(endpoint_entry.get("retry_count", entry.get("retry_count"))),
        retry_delay=_optional_float(endpoint_entry.get("retry_delay", entry.get("retry_delay"))),
    )


def _generation_spec_from_entry(
    entry: dict[str, Any],
    *,
    default: GenerationSpec,
) -> GenerationSpec:
    generation_entry = entry.get("generation", {})
    if not isinstance(generation_entry, dict):
        raise TypeError("generation must be a TOML table")
    max_tokens = generation_entry.get("max_tokens", entry.get("max_tokens"))
    if max_tokens is None:
        max_tokens = generation_entry.get(
            "max_new_tokens", entry.get("max_new_tokens", default.max_tokens)
        )
    raw_use_completions_api = generation_entry.get(
        "use_completions_api",
        entry.get("use_completions_api", default.use_completions_api),
    )
    if not isinstance(raw_use_completions_api, bool):
        raise TypeError("use_completions_api must be a boolean")
    return GenerationSpec(
        max_tokens=_positive_int(max_tokens, field_name="max_tokens"),
        temperature=_optional_float(
            generation_entry.get("temperature", entry.get("temperature", default.temperature))
        ),
        top_p=_optional_float(generation_entry.get("top_p", entry.get("top_p", default.top_p))),
        repetition_penalty=_optional_float(
            generation_entry.get(
                "repetition_penalty",
                entry.get("repetition_penalty", default.repetition_penalty),
            )
        ),
        frequency_penalty=_optional_float(
            generation_entry.get(
                "frequency_penalty", entry.get("frequency_penalty", default.frequency_penalty)
            )
        ),
        stop_tokens=_optional_str_list(
            generation_entry.get("stop_tokens", entry.get("stop_tokens", default.stop_tokens))
        ),
        use_completions_api=raw_use_completions_api,
    )


def _default_api_key_env(backend: str) -> str | None:
    if backend == "remote":
        return "ANTARES_API_KEY"
    return None


def _adapter_from_entry(
    entry: dict[str, Any],
    *,
    default: str,
) -> str:
    if entry.get("adapter") is not None:
        return _required_str(entry["adapter"], field_name="adapter")
    return default


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return _required_str(value, field_name="value")


def _required_str(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    return value


def _required_str_list(value: object, *, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{field_name} must be a list of strings")
    return list(value)


def _positive_int(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TypeError(f"{field_name} must be a positive integer")
    return value


def _optional_str_list(value: object) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise TypeError(f"Expected a list of strings, got {type(value).__name__}")


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("Expected integer-compatible value, got bool")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise TypeError("Expected a finite integer-compatible value")
        return int(value)
    if isinstance(value, str):
        return int(value)
    raise TypeError(f"Expected integer-compatible value, got {type(value).__name__}")


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("Expected float-compatible value, got bool")
    if isinstance(value, int | float | str):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise TypeError("Expected a finite float-compatible value")
        return parsed
    raise TypeError(f"Expected float-compatible value, got {type(value).__name__}")
