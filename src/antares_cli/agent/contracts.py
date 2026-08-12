# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Canonical agent contracts shared by prompts, adapters, and loop components."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.output.finding import Finding, TrajectoryEntry
from antares_cli.output.renderer import AgentStateSnapshot

TERMINAL_TOOL_NAME = "terminal"
BASH_TOOL_NAME = "bash"
SUBMIT_VULNERABLE_FILES_TOOL = "submit_vulnerable_files"
SUBMIT_NO_VULNERABILITY_FOUND_TOOL = "submit_no_vulnerability_found"
RANKED_FILES_ARGUMENT = "ranked_files"
RANKED_FILE_ARGUMENT_ALIASES = (RANKED_FILES_ARGUMENT, "files", "file_paths")
SUBMIT_FILE_PATH_FIELD_ALIASES = ("file_path", "path", "file")

ProgressCallback = Callable[[AgentStateSnapshot, Finding | None], None]


class BuildAgentStateFn(Protocol):
    def __call__(
        self,
        *,
        messages: list[dict[str, str]] | None = None,
        trajectory: list[TrajectoryEntry] | None = None,
    ) -> AgentStateSnapshot: ...


def normalize_tool_name(tool_name: str) -> str:
    return tool_name.strip().lower()


_SUBMIT_TOOL_NAMES = frozenset(
    {
        SUBMIT_VULNERABLE_FILES_TOOL,
        SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
    }
)


def is_submit_tool_name(tool_name: str) -> bool:
    return normalize_tool_name(tool_name) in _SUBMIT_TOOL_NAMES


def is_submit_tool_call(parsed_call: ParsedToolCall) -> bool:
    return is_submit_tool_name(parsed_call.tool_name)
