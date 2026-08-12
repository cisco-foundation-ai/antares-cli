# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Runtime assembly for Antares workflows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from antares_cli.agent.loop import AntaresAgentLoop
from antares_cli.agent.model_adapter import ModelAdapter, resolve_model_adapter
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.config import AntaresSettings
from antares_cli.inference.backend import InferenceBackend
from antares_cli.inference.profiles import (
    EndpointSpec,
    GenerationSpec,
    InferenceProfile,
    ModelSpec,
    resolve_model_spec,
    resolve_profile,
)
from antares_cli.inference.remote import RemoteInferenceBackend
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.tools.readonly_workspace import ReadOnlyRepositorySnapshot


class RuntimeConfigurationError(ValueError):
    """Raised when workflow runtime configuration is invalid."""


@dataclass(slots=True)
class RuntimeOptions:
    target: Path
    profile: str | None = None
    model: str | None = None
    backend: str | None = None
    endpoint: str | None = None
    api_key: str | None = None


@dataclass(slots=True)
class RuntimeContext:
    settings: AntaresSettings
    inference_backend: InferenceBackend | None
    cwe_database: CweDatabase
    model_label: str
    selected_profile: InferenceProfile | None
    model_spec: ModelSpec | None
    model_adapter: ModelAdapter | None

    def create_agent_loop(
        self,
        target: Path,
        *,
        snapshot: ReadOnlyRepositorySnapshot | None = None,
    ) -> AntaresAgentLoop:
        return AntaresAgentLoop(
            tool_router=ToolRouter(target, snapshot=snapshot),
            cwe_database=self.cwe_database,
            inference_backend=self.inference_backend,
            model_label=self.model_label,
            model_adapter=self.model_adapter,
        )


@dataclass(slots=True)
class RuntimeResolution:
    backend: str | None
    endpoint: str | None
    model: str
    api_key: str | None
    selected_profile: InferenceProfile | None
    model_spec: ModelSpec | None


@dataclass(slots=True, frozen=True)
class BackendSettings:
    backend_name: str
    generation: GenerationSpec
    context_window: int
    endpoint_spec: EndpointSpec | None


class RuntimeFactory:
    """Builds the shared runtime dependencies used by all Antares adapters."""

    def load_cwe_database(self) -> CweDatabase:
        return CweDatabase.load_default()

    def build(self, options: RuntimeOptions) -> RuntimeContext:
        base_settings = AntaresSettings.load(start_path=options.target)
        resolution = _resolve_runtime_inputs(options, base_settings)
        settings = _load_runtime_settings(base_settings, resolution)
        cwe_database = self.load_cwe_database()
        inference_backend = _resolve_backend(settings, resolution)
        try:
            model_label = options.profile if options.profile is not None else settings.model
            model_adapter = _resolve_model_adapter(
                selected_profile=resolution.selected_profile,
                model_spec=resolution.model_spec,
                model_label=model_label,
            )
            return RuntimeContext(
                settings=settings,
                inference_backend=inference_backend,
                cwe_database=cwe_database,
                model_label=model_label,
                selected_profile=resolution.selected_profile,
                model_spec=resolution.model_spec,
                model_adapter=model_adapter,
            )
        except BaseException:
            inference_backend.close()
            raise


def _resolve_runtime_inputs(
    options: RuntimeOptions,
    base_settings: AntaresSettings,
) -> RuntimeResolution:
    selected_profile: InferenceProfile | None = None
    if options.profile is not None:
        selected_profile = _resolve_named_profile(options.profile)

    backend = options.backend or (
        selected_profile.backend if selected_profile is not None else base_settings.backend
    )
    endpoint = options.endpoint or (
        selected_profile.endpoint if selected_profile is not None else base_settings.endpoint
    )
    model = options.model or (
        selected_profile.model_id if selected_profile is not None else base_settings.model
    )
    api_key = options.api_key or (
        selected_profile.api_key if selected_profile is not None else base_settings.api_key
    )

    requested_model = (model or "").strip()
    if not requested_model:
        raise RuntimeConfigurationError(
            "Inference requires an explicit model ID. Set ANTARES_MODEL, pass --model, "
            "or configure model in ~/.antares/profiles.toml."
        )
    model_spec = resolve_model_spec(requested_model)
    return RuntimeResolution(
        backend=backend,
        endpoint=endpoint,
        model=requested_model,
        api_key=api_key,
        selected_profile=selected_profile,
        model_spec=model_spec,
    )


def _resolve_named_profile(profile: str) -> InferenceProfile:
    connection = resolve_profile(profile)
    if connection is None:
        raise RuntimeConfigurationError(
            f"Unknown profile '{profile}'. Configure profiles in "
            "~/.antares/profiles.toml or set ANTARES_ENDPOINT + ANTARES_API_KEY."
        )
    return connection


def _load_runtime_settings(
    base_settings: AntaresSettings,
    resolution: RuntimeResolution,
) -> AntaresSettings:
    return AntaresSettings.model_validate(
        {
            **base_settings.model_dump(),
            "model": resolution.model,
            "backend": resolution.backend,
            "endpoint": resolution.endpoint,
            "api_key": resolution.api_key,
        }
    )


def _resolve_backend(
    settings: AntaresSettings,
    resolution: RuntimeResolution,
) -> InferenceBackend:
    inference_backend = _build_inference_backend(
        settings,
        resolution.selected_profile,
        resolution.model_spec,
        explicit_api_key=resolution.api_key,
    )
    if inference_backend is not None:
        return inference_backend
    raise RuntimeConfigurationError(
        f"Backend '{settings.backend}' was requested but is not available. "
        "Provide model weights or configure a remote endpoint/API key."
    )


def _resolve_model_adapter(
    *,
    selected_profile: InferenceProfile | None,
    model_spec: ModelSpec | None,
    model_label: str,
) -> ModelAdapter | None:
    if selected_profile is not None:
        return resolve_model_adapter(selected_profile.adapter)
    if model_spec is not None:
        return resolve_model_adapter(model_spec.adapter)
    return resolve_model_adapter(model_label)


def _build_inference_backend(
    settings: AntaresSettings,
    selected_profile: InferenceProfile | None,
    model_spec: ModelSpec | None,
    *,
    explicit_api_key: str | None,
) -> InferenceBackend | None:
    backend_settings = _backend_settings(settings, selected_profile, model_spec)
    if backend_settings.backend_name in {"auto", "remote"} and settings.endpoint:
        return _build_remote_backend(settings, backend_settings, explicit_api_key)
    return None


def _backend_settings(
    settings: AntaresSettings,
    selected_profile: InferenceProfile | None,
    model_spec: ModelSpec | None,
) -> BackendSettings:
    behavior = selected_profile or model_spec
    return BackendSettings(
        backend_name=settings.backend.lower(),
        generation=behavior.generation if behavior is not None else GenerationSpec(),
        context_window=behavior.context_window if behavior is not None else settings.context_window,
        endpoint_spec=selected_profile.endpoint_spec if selected_profile is not None else None,
    )


def _build_remote_backend(
    settings: AntaresSettings,
    backend_settings: BackendSettings,
    explicit_api_key: str | None,
) -> RemoteInferenceBackend:
    endpoint_spec = backend_settings.endpoint_spec
    generation = backend_settings.generation
    if settings.endpoint is None:
        raise RuntimeConfigurationError("Remote inference requires a configured endpoint")
    return RemoteInferenceBackend(
        model_id=settings.model,
        endpoint=settings.endpoint,
        context_window=backend_settings.context_window,
        timeout_seconds=_endpoint_timeout(endpoint_spec, settings),
        api_key=explicit_api_key
        or (endpoint_spec.resolved_api_key if endpoint_spec is not None else None)
        or settings.api_key,
        retry_count=_endpoint_retry_count(endpoint_spec),
        retry_delay=_endpoint_retry_delay(endpoint_spec),
        max_tokens=generation.max_tokens,
        temperature=generation.temperature,
        top_p=generation.top_p,
        repetition_penalty=generation.repetition_penalty,
        frequency_penalty=generation.frequency_penalty,
        stop_tokens=generation.stop_tokens,
        use_completions_api=generation.use_completions_api,
    )


def _endpoint_timeout(endpoint_spec: EndpointSpec | None, settings: AntaresSettings) -> float:
    if endpoint_spec is not None and endpoint_spec.timeout_seconds is not None:
        return endpoint_spec.timeout_seconds
    return settings.remote_timeout_seconds


def _endpoint_retry_count(endpoint_spec: EndpointSpec | None) -> int:
    if endpoint_spec is not None and endpoint_spec.retry_count is not None:
        return endpoint_spec.retry_count
    return 6


def _endpoint_retry_delay(endpoint_spec: EndpointSpec | None) -> float:
    if endpoint_spec is not None and endpoint_spec.retry_delay is not None:
        return endpoint_spec.retry_delay
    return 5.0
