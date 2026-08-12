# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Non-interactive JSON command surface for automation and integrations."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer

from antares_cli.agent.execution_policy import resolve_terminal_call_budget
from antares_cli.commands._selection_options import parse_cwe_level, parse_scan_scope
from antares_cli.commands._workflow import (
    raise_cli_error,
    record_failed_run_best_effort,
    record_workflow_run_best_effort,
    workflow_result_has_operational_failures,
)
from antares_cli.core.cwe_selection_limits import (
    DEFAULT_AUTOMATIC_CWE_LIMIT,
    resolve_automatic_cwe_limit,
)
from antares_cli.core.service import QueryRequest, SecurityWorkflowService, SweepRequest
from antares_cli.core.worker_limits import DEFAULT_SWEEP_WORKERS, resolve_sweep_worker_count
from antares_cli.run_history import (
    capture_invocation,
)

tool_app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Non-interactive JSON interface for automation and integrations.",
)
MAX_TOOL_STDIN_CHARS = 1_000_000
MAX_TOOL_JSON_DEPTH = 256
_SHARED_REQUEST_KEYS = frozenset(
    {
        "target",
        "cwe_ids",
        "query",
        "profile",
        "model",
        "backend",
        "endpoint",
        "api_key",
        "tool_budget",
        "allow_sensitive_files",
    }
)
_SWEEP_REQUEST_KEYS = _SHARED_REQUEST_KEYS | {
    "workers",
    "selection",
    "scope",
    "cwe_level",
    "max_cwes",
}
_SELECTION_KEYS = frozenset({"scope", "cwe_level", "max_cwes"})


@tool_app.command("query")
def tool_query_command(
    stdin: bool = typer.Option(False, "--stdin", help="Read request JSON from stdin."),
) -> None:
    """Run one explicit-CWE investigation from a JSON stdin request."""
    if not stdin:
        raise typer.BadParameter("tool query requires --stdin")
    payload = _read_stdin_payload()
    _validate_payload_keys(payload, command="query")
    cwe_ids = _string_list(payload.get("cwe_ids"))
    if not cwe_ids:
        raise typer.BadParameter("tool query requires cwe_ids")
    invocation = capture_invocation()
    request = QueryRequest(
        target=_target_path(payload.get("target", ".")),
        query=_optional_string(payload.get("query"), field_name="query"),
        cwe_ids=cwe_ids,
        profile=_optional_string(payload.get("profile"), field_name="profile"),
        model=_optional_string(payload.get("model"), field_name="model"),
        backend=_optional_string(payload.get("backend"), field_name="backend"),
        endpoint=_optional_string(payload.get("endpoint"), field_name="endpoint"),
        api_key=_optional_string(payload.get("api_key"), field_name="api_key"),
        terminal_call_budget=_terminal_call_budget(payload),
        allow_sensitive_files=_sensitive_file_array(payload),
    )
    try:
        result = SecurityWorkflowService().run_query(request)
    except Exception as error:
        record_failed_run_best_effort(
            invocation=invocation,
            mode="tool_query",
            target=request.target,
            error=error,
            request_metadata={
                "query": request.query,
                "cwe_ids": request.cwe_ids,
                "model": request.model,
                "backend": request.backend,
                "profile": request.profile,
                "allowed_sensitive_files": request.allow_sensitive_files,
            },
        )
        raise_cli_error(error)
    has_operational_failures = workflow_result_has_operational_failures(result)
    print(result.to_json(), flush=True)
    record_workflow_run_best_effort(
        result,
        invocation=invocation,
        target=request.target,
        status="incomplete" if has_operational_failures else "completed",
    )
    if has_operational_failures:
        raise typer.Exit(code=2)


@tool_app.command("sweep")
def tool_sweep_command(
    stdin: bool = typer.Option(False, "--stdin", help="Read request JSON from stdin."),
) -> None:
    """Run a multi-CWE sweep from a JSON stdin request."""
    if not stdin:
        raise typer.BadParameter("tool sweep requires --stdin")
    payload = _read_stdin_payload()
    _validate_payload_keys(payload, command="sweep")
    invocation = capture_invocation()
    request = SweepRequest(
        target=_target_path(payload.get("target", ".")),
        query=_optional_string(payload.get("query"), field_name="query"),
        cwe_ids=_string_list(payload.get("cwe_ids")),
        workers=_worker_count(payload),
        profile=_optional_string(payload.get("profile"), field_name="profile"),
        model=_optional_string(payload.get("model"), field_name="model"),
        backend=_optional_string(payload.get("backend"), field_name="backend"),
        endpoint=_optional_string(payload.get("endpoint"), field_name="endpoint"),
        api_key=_optional_string(payload.get("api_key"), field_name="api_key"),
        scope=parse_scan_scope(_selection_string(payload, "scope", "auto")),
        cwe_level=parse_cwe_level(_selection_string(payload, "cwe_level", "all")),
        max_cwes=_automatic_cwe_limit(payload),
        terminal_call_budget=_terminal_call_budget(payload),
        allow_sensitive_files=_sensitive_file_array(payload),
    )
    try:
        result = SecurityWorkflowService().run_cwe_sweep(request)
    except Exception as error:
        record_failed_run_best_effort(
            invocation=invocation,
            mode="tool_sweep",
            target=request.target,
            error=error,
            request_metadata={
                "query": request.query,
                "cwe_ids": request.cwe_ids,
                "scope": request.scope,
                "cwe_level": request.cwe_level,
                "max_cwes": request.max_cwes,
                "model": request.model,
                "backend": request.backend,
                "profile": request.profile,
                "allowed_sensitive_files": request.allow_sensitive_files,
            },
        )
        raise_cli_error(error)
    has_operational_failures = workflow_result_has_operational_failures(result)
    print(result.to_json(), flush=True)
    record_workflow_run_best_effort(
        result,
        invocation=invocation,
        target=request.target,
        status="incomplete" if has_operational_failures else "completed",
    )
    if has_operational_failures:
        raise typer.Exit(code=2)


def _read_stdin_payload() -> dict[str, Any]:
    raw_payload = sys.stdin.read(MAX_TOOL_STDIN_CHARS + 1)
    if len(raw_payload) > MAX_TOOL_STDIN_CHARS:
        raise typer.BadParameter(f"stdin JSON exceeds the {MAX_TOOL_STDIN_CHARS:,}-character limit")
    _validate_json_depth(raw_payload)
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as error:
        raise typer.BadParameter(f"Invalid stdin JSON: {error}") from error
    except RecursionError as error:
        raise typer.BadParameter("Invalid stdin JSON: nesting is too deep") from error
    except ValueError as error:
        raise typer.BadParameter("Invalid stdin JSON") from error
    if not isinstance(payload, dict):
        raise typer.BadParameter("stdin JSON must be an object")
    return payload


def _validate_json_depth(raw_payload: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in raw_payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_TOOL_JSON_DEPTH:
                raise typer.BadParameter(
                    f"Invalid stdin JSON: nesting exceeds {MAX_TOOL_JSON_DEPTH} levels"
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _validate_payload_keys(payload: dict[str, Any], *, command: str) -> None:
    allowed_keys = _SHARED_REQUEST_KEYS if command == "query" else _SWEEP_REQUEST_KEYS
    unknown_keys = sorted(payload.keys() - allowed_keys)
    if unknown_keys:
        raise typer.BadParameter(f"Unknown {command} request field(s): {', '.join(unknown_keys)}")
    if command == "query":
        return
    selection = payload.get("selection")
    if selection is None:
        return
    if not isinstance(selection, dict):
        raise typer.BadParameter("selection must be an object or null")
    unknown_selection_keys = sorted(selection.keys() - _SELECTION_KEYS)
    if unknown_selection_keys:
        raise typer.BadParameter("Unknown selection field(s): " + ", ".join(unknown_selection_keys))
    duplicate_selection_keys = sorted(selection.keys() & payload.keys() & _SELECTION_KEYS)
    if duplicate_selection_keys:
        raise typer.BadParameter(
            "Selection field(s) must appear either at the top level or in selection, not both: "
            + ", ".join(duplicate_selection_keys)
        )


def _target_path(value: object) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise typer.BadParameter("target must be a non-empty string")
    target = Path(value).expanduser()
    if not target.exists():
        raise typer.BadParameter(f"target does not exist: {target}")
    if not target.is_dir():
        raise typer.BadParameter(f"target must be a repository directory: {target}")
    if not os.access(target, os.R_OK):
        raise typer.BadParameter(f"target is not readable: {target}")
    return target


def _optional_string(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise typer.BadParameter(f"{field_name} must be a string or null")
    return value


def _selection_string(payload: dict[str, Any], key: str, default: str) -> str:
    selection = payload.get("selection")
    if isinstance(selection, dict) and selection.get(key) is not None:
        value = selection[key]
        if not isinstance(value, str):
            raise typer.BadParameter(f"{key} must be a string")
        return value
    value = payload.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise typer.BadParameter(f"{key} must be a string")
    return value


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise typer.BadParameter("cwe_ids list entries must be strings")
        return [item.strip() for item in value if item.strip()]
    raise typer.BadParameter("cwe_ids must be a string or list")


def _sensitive_file_array(payload: dict[str, Any]) -> list[str]:
    value = payload.get("allow_sensitive_files")
    if value is None:
        return []
    if not isinstance(value, list):
        raise typer.BadParameter("allow_sensitive_files must be an array of relative paths")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise typer.BadParameter("allow_sensitive_files entries must be non-empty strings")
    return [item.strip() for item in value]


def _positive_integer(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise typer.BadParameter(f"{field_name} must be a positive integer")
    try:
        parsed = int(value)
    except ValueError as error:
        raise typer.BadParameter(f"{field_name} must be a positive integer") from error
    if parsed < 1:
        raise typer.BadParameter(f"{field_name} must be a positive integer")
    return parsed


def _worker_count(payload: dict[str, Any]) -> int:
    value = _positive_integer(
        payload.get("workers", DEFAULT_SWEEP_WORKERS),
        field_name="workers",
    )
    try:
        return resolve_sweep_worker_count(value)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


def _terminal_call_budget(payload: dict[str, Any]) -> int:
    raw_value = payload.get("tool_budget")
    if raw_value is None:
        return resolve_terminal_call_budget(None)
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, str)):
        raise typer.BadParameter("tool_budget must be an integer")
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise typer.BadParameter("tool_budget must be an integer") from error
    try:
        return resolve_terminal_call_budget(value)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


def _automatic_cwe_limit(payload: dict[str, Any]) -> int:
    selection = payload.get("selection")
    raw_value = selection.get("max_cwes") if isinstance(selection, dict) else None
    if raw_value is None:
        raw_value = payload.get("max_cwes", DEFAULT_AUTOMATIC_CWE_LIMIT)
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, str)):
        raise typer.BadParameter("max_cwes must be an integer")
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise typer.BadParameter("max_cwes must be an integer") from error
    try:
        return resolve_automatic_cwe_limit(value)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
