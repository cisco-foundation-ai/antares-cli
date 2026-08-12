# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Workflow metadata and reporting helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from antares_cli.agent.subagent import WorkerResult
from antares_cli.core.runtime import RuntimeContext

SCHEMA_VERSION = "1.0"


def workflow_metadata(
    *,
    target: Path,
    query: str | None,
    cwe_ids: list[str],
    model: str,
    backend: str,
    profile: str | None,
    terminal_call_budget: int,
    allowed_sensitive_files: tuple[str, ...] = (),
    mode: str = "query",
) -> dict[str, Any]:
    stable_input = {
        "target": target.resolve().name,
        "query": query or "",
        "cwe_ids": cwe_ids,
        "model": model,
        "backend": backend,
        "profile": profile or "",
        "terminal_call_budget": terminal_call_budget,
        "allowed_sensitive_files": list(allowed_sensitive_files),
        "mode": mode,
    }
    request_hash = hashlib.sha256(
        json.dumps(stable_input, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_hash[:16],
        "mode": mode,
        "model": model,
        "backend": backend,
        "profile": profile,
        "cwe_ids": cwe_ids,
        "query": query,
        "target": target.resolve().name,
        "terminal_call_budget": terminal_call_budget,
        "allowed_sensitive_files": list(allowed_sensitive_files),
        "reproducibility": {
            "request_hash": request_hash,
            "deterministic_ordering": True,
            "remote_provider_may_vary": backend == "remote",
            "safe_for_cache_reuse": False,
            "cache_reuse_note": (
                "Request identity excludes source contents and the deployed model revision."
            ),
        },
    }


def model_configuration_metadata(runtime: RuntimeContext) -> dict[str, Any]:
    settings_payload = _redact_connection_fields(runtime.settings.model_dump())
    backend_payload = _backend_payload(runtime)
    profile_payload = _profile_payload(runtime)
    return {
        "settings": settings_payload,
        "model_label": runtime.model_label,
        "backend": backend_payload,
        "model_adapter": runtime.model_adapter.name if runtime.model_adapter is not None else None,
        "model_spec": asdict(runtime.model_spec) if runtime.model_spec is not None else None,
        "selected_profile": profile_payload,
    }


def per_cwe_results(
    worker_results: list[WorkerResult], ordered_cwe_ids: list[str]
) -> list[dict[str, Any]]:
    by_task_id = {worker_result.task_id: worker_result for worker_result in worker_results}
    return [
        _per_cwe_result_payload(by_task_id.get(cwe_id.replace("CWE-", "cwe-")), cwe_id)
        for cwe_id in ordered_cwe_ids
    ]


def _backend_payload(runtime: RuntimeContext) -> dict[str, Any]:
    backend = runtime.inference_backend
    if backend is None:
        return {
            "class": None,
            "backend_name": None,
            "model_id": runtime.settings.model,
            "context_window": None,
        }
    return _redact_connection_fields(
        {str(k): _json_safe_value(v) for k, v in backend.metadata().items()}
    )


def _profile_payload(runtime: RuntimeContext) -> dict[str, Any] | None:
    if runtime.selected_profile is None:
        return None
    return _redact_connection_fields(asdict(runtime.selected_profile))


def _redact_connection_fields(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    for key in ("endpoint", "url"):
        if redacted.get(key):
            redacted[key] = "<configured>"
    for key in ("api_key", "api_key_env", "url_env"):
        if redacted.get(key):
            redacted[key] = "<redacted>"
    endpoint_spec = redacted.get("endpoint_spec")
    if isinstance(endpoint_spec, dict):
        redacted["endpoint_spec"] = _redact_connection_fields(endpoint_spec)
    return redacted


def _per_cwe_result_payload(worker_result: WorkerResult | None, cwe_id: str) -> dict[str, Any]:
    if worker_result is None:
        return {
            "cwe_id": cwe_id,
            "finding_count": 0,
            "tool_call_count": 0,
            "duration_seconds": 0.0,
            "investigation_trace": None,
            "error_message": "worker result missing",
            "failed_tool_calls": 0,
            "retried_turns": 0,
        }
    return {
        "cwe_id": cwe_id,
        "finding_count": len(worker_result.findings),
        "tool_call_count": worker_result.tool_call_count,
        "duration_seconds": worker_result.duration_seconds,
        "investigation_trace": worker_result.investigation_trace,
        "error_message": worker_result.error_message,
        "failed_tool_calls": worker_result.failed_tool_calls,
        "retried_turns": worker_result.retried_turns,
    }


def _json_safe_value(value: Any) -> object:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe_value(item) for item in value]
    return str(value)
