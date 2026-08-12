# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Routes tool names to local implementations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from antares_cli.agent._text_utils import strip_bpe_spaces as _strip_bpe_spaces
from antares_cli.agent.contracts import TERMINAL_TOOL_NAME
from antares_cli.tools.readonly_workspace import ReadOnlyRepositorySnapshot
from antares_cli.tools.shell_exec import (
    MAX_TOOL_OUTPUT_CHARS,
    _parse_read_only_command_stages,
    _references_sensitive_path,
    _validate_read_only_stage_paths,
    run_bash,
)

MAX_READ_FILE_CHARS = 50_000
MAX_READ_FILE_BYTES = 10_000_000
MAX_TOOL_ERROR_CHARS = 2_000
_TOOL_ERROR_TRUNCATION_SUFFIX = "...[tool error truncated]"


@dataclass(slots=True)
class ToolExecutionResult:
    success: bool
    output: Any
    error_message: str | None = None


def bound_tool_error(message: object) -> str:
    raw_message = str(message) if message is not None else "Unknown tool error."
    visible_message = "".join(
        character if character in {"\n", "\t"} or character.isprintable() else repr(character)[1:-1]
        for character in raw_message[:MAX_TOOL_ERROR_CHARS]
    )
    if len(raw_message) <= MAX_TOOL_ERROR_CHARS and len(visible_message) <= MAX_TOOL_ERROR_CHARS:
        return visible_message
    retained = MAX_TOOL_ERROR_CHARS - len(_TOOL_ERROR_TRUNCATION_SUFFIX)
    return visible_message[:retained] + _TOOL_ERROR_TRUNCATION_SUFFIX


def _read_file(
    path: str,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
    cwd: str | Path | None = None,
) -> dict[str, object]:
    """Read a file with optional line range. Returns numbered lines."""
    # Reject glob patterns and directory paths with a helpful error message
    if "*" in path or "?" in path:
        raise ValueError(
            f"read_file does not support glob patterns: {path}. "
            "Use terminal with `find` or `ls` to list matching files, "
            "then call read_file on each individual file."
        )
    file_path = Path(path)
    if not file_path.is_absolute() and cwd:
        file_path = Path(cwd) / file_path
    if file_path.is_dir():
        raise ValueError(
            f"read_file does not work on directories: {file_path}. "
            "Use `terminal` with `ls` or `find` to list directory contents, "
            "then call read_file on individual files."
        )
    if not file_path.is_file():
        raise ValueError(f"File not found: {file_path}")
    file_size = file_path.stat().st_size
    if file_size > MAX_READ_FILE_BYTES:
        raise ValueError(
            f"File is too large for read_file ({file_size:,} bytes; "
            f"limit {MAX_READ_FILE_BYTES:,}). Use terminal with head or sed to inspect a slice."
        )

    start = _positive_line_number(start_line, field_name="start_line", default=1)
    end = _positive_line_number(end_line, field_name="end_line", default=None)
    if start is None:
        start = 1
    if end is not None and end < start:
        raise ValueError("end_line must be greater than or equal to start_line")

    output_parts: list[str] = []
    output_length = 0
    total_lines = 0
    last_selected_line: int | None = None
    truncated = False
    has_more = False
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            total_lines = line_number
            if end is not None and line_number > end:
                has_more = True
                break
            if line_number < start:
                continue
            line = raw_line.rstrip("\r\n")
            rendered_line = f"{line_number:>5}: {line}"
            separator = "\n" if output_parts else ""
            remaining = MAX_READ_FILE_CHARS - output_length
            addition = f"{separator}{rendered_line}"
            if len(addition) > remaining:
                if remaining > 0:
                    output_parts.append(addition[:remaining])
                    output_length += remaining
                truncated = True
                has_more = True
            else:
                output_parts.append(addition)
                output_length += len(addition)
            last_selected_line = line_number
            if truncated:
                break

    numbered_output = "".join(output_parts)
    showing_lines = f"{start}-{last_selected_line}" if last_selected_line is not None else "none"

    return {
        "path": str(file_path),
        "total_lines": None if has_more else total_lines,
        "has_more": has_more,
        "showing_lines": showing_lines,
        "stdout": numbered_output,
        "truncated": truncated,
    }


def _positive_line_number(
    value: int | None,
    *,
    field_name: str,
    default: int | None,
) -> int | None:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _terminal(
    command: str,
    *,
    max_chars: int = 2000,
    cwd: str | Path | None = None,
    allowed_sensitive_files: tuple[str, ...] = (),
) -> dict[str, object]:
    """Run a read-only terminal command in the repository snapshot."""
    result = run_bash(
        command,
        cwd=cwd,
        timeout_seconds=10,
        allowed_sensitive_files=allowed_sensitive_files,
    )
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        max_chars = 2000
    if max_chars <= 0:
        max_chars = 2000

    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    truncated = bool(result.get("truncated", False))

    if len(stdout) > max_chars:
        stdout = stdout[:max_chars]
        truncated = True
    if stderr and len(stderr) > max_chars:
        stderr = stderr[:max_chars]
        truncated = True

    result["stdout"] = stdout
    result["stderr"] = stderr
    result["truncated"] = truncated
    return result


class ToolRouter:
    """Dispatches named tools into concrete Python implementations."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        snapshot: ReadOnlyRepositorySnapshot | None = None,
        allow_sensitive_files: list[str] | tuple[str, ...] = (),
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        if snapshot is None:
            self._owned_snapshot: ReadOnlyRepositorySnapshot | None = ReadOnlyRepositorySnapshot(
                self.workspace_root,
                allow_sensitive_files=allow_sensitive_files,
            )
            self.execution_root = self._owned_snapshot.root
            self.allowed_sensitive_files = self._owned_snapshot.allowed_sensitive_files
        else:
            self._owned_snapshot = None
            self.execution_root = snapshot.root
            self.allowed_sensitive_files = snapshot.allowed_sensitive_files
        self._tools: dict[str, Callable[..., Any]] = {
            TERMINAL_TOOL_NAME: partial(
                _terminal,
                allowed_sensitive_files=self.allowed_sensitive_files,
            ),
            "read_file": _read_file,
        }

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> ToolExecutionResult:
        tool_name = tool_name.strip().lower().replace(" ", "")
        if tool_name not in self._tools:
            fuzzy_match = self._fuzzy_resolve(tool_name)
            if fuzzy_match is not None:
                tool_name = fuzzy_match
        if tool_name not in self._tools:
            return ToolExecutionResult(
                success=False,
                output=None,
                error_message=bound_tool_error(f"Unsupported tool: {tool_name}. Use terminal."),
            )
        normalized_arguments = self._normalize_arguments(arguments)
        argument_error = _validate_tool_arguments(tool_name, normalized_arguments)
        if argument_error is not None:
            return ToolExecutionResult(
                success=False,
                output=None,
                error_message=bound_tool_error(argument_error),
            )
        normalized_arguments["cwd"] = str(self.execution_root)
        workspace_check = self._validate_workspace_paths(tool_name, normalized_arguments)
        if workspace_check is not None:
            return ToolExecutionResult(
                success=False,
                output=None,
                error_message=bound_tool_error(workspace_check),
            )
        try:
            tool_output = self._tools[tool_name](**normalized_arguments)
        except Exception as error:
            return ToolExecutionResult(
                success=False,
                output=None,
                error_message=bound_tool_error(error),
            )
        return ToolExecutionResult(success=True, output=tool_output)

    def close(self) -> None:
        if self._owned_snapshot is not None:
            self._owned_snapshot.close()
            self._owned_snapshot = None

    def available_tool_names(self) -> list[str]:
        return sorted(self._tools)

    def _normalize_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        cleaned_arguments: dict[str, Any] = {}
        for key, value in arguments.items():
            clean_key = key.replace(" ", "")
            if isinstance(value, str) and clean_key != "command":
                value = _strip_bpe_spaces(value)
            cleaned_arguments[clean_key] = value
        return cleaned_arguments

    def _fuzzy_resolve(self, mangled_name: str) -> str | None:
        import re

        dehexed = re.sub(r"_[0-9a-f]{2}_", "_", mangled_name)
        if dehexed in self._tools:
            return dehexed
        stripped = re.sub(r"[\d_]+$", "", dehexed)
        if stripped in self._tools:
            return stripped
        candidates = [name for name in self._tools if name.startswith(stripped)]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _validate_workspace_paths(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str | None:
        if tool_name == "read_file":
            path = arguments.get("path")
            if isinstance(path, str) and _references_sensitive_path(
                path,
                self.allowed_sensitive_files,
            ):
                return f"Sensitive path is blocked: {path}"
            if isinstance(path, str) and Path(path).is_absolute():
                if not self._path_stays_inside_workspace(path):
                    return f"Path is outside the repository workspace: {path}"
                return "Absolute repository paths are blocked. Use relative paths instead."
            if isinstance(path, str) and not self._path_stays_inside_workspace(path):
                return f"Path is outside the repository workspace: {path}"
            return None

        if tool_name != TERMINAL_TOOL_NAME:
            return None

        command = arguments.get("command")
        if not isinstance(command, str):
            return None
        try:
            stages = _parse_read_only_command_stages(command)
        except ValueError:
            return None

        for stage in stages:
            path_error = _validate_read_only_stage_paths(
                stage,
                self.workspace_root,
                self.allowed_sensitive_files,
            )
            if path_error is not None:
                return path_error
        return None

    def _path_stays_inside_workspace(self, raw_path: str) -> bool:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        try:
            resolved = candidate.resolve()
        except ValueError:
            return False
        except OSError:
            resolved = candidate.absolute()
        return resolved == self.workspace_root or self.workspace_root in resolved.parents


def _validate_tool_arguments(tool_name: str, arguments: dict[str, Any]) -> str | None:
    if tool_name == TERMINAL_TOOL_NAME:
        allowed_arguments = {"command", "max_chars"}
        required_argument = "command"
    elif tool_name == "read_file":
        allowed_arguments = {"path", "start_line", "end_line"}
        required_argument = "path"
    else:
        return None

    unknown_arguments = sorted(set(arguments) - allowed_arguments)
    if unknown_arguments:
        return f"Unsupported argument(s) for {tool_name}: {', '.join(unknown_arguments)}"
    required_value = arguments.get(required_argument)
    if not isinstance(required_value, str) or not required_value.strip():
        return f"{tool_name} requires a non-empty string '{required_argument}' argument"
    if tool_name == TERMINAL_TOOL_NAME and "max_chars" in arguments:
        max_chars = arguments["max_chars"]
        if isinstance(max_chars, bool) or not isinstance(max_chars, int):
            return "max_chars must be an integer"
        if max_chars < 1 or max_chars > MAX_TOOL_OUTPUT_CHARS:
            return f"max_chars must be between 1 and {MAX_TOOL_OUTPUT_CHARS:,}"
    return None
