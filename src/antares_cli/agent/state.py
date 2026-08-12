# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared mutable state and result types for agent execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from antares_cli.agent.model_adapter import ModelOutputParser
from antares_cli.agent.quarantine import ContentQuarantine
from antares_cli.agent.trace import SessionTrace
from antares_cli.output.finding import Finding, ReportSummary, TrajectoryEntry


@dataclass
class ModelSessionState:
    """Mutable per-session state shared across model turns, importable by shell."""

    findings: list[Finding]
    dedupe_keys: set[tuple[str, str]]
    reasoning_log: list[str]
    tool_call_count: int
    messages: list[dict[str, str]]
    session_trace: SessionTrace
    content_quarantine: ContentQuarantine
    output_parser: ModelOutputParser
    done_signaled: bool
    answer_text: str
    consecutive_errors: int
    retried_turns_count: int
    failed_tool_calls_count: int
    seen_tool_calls: set[str]
    started_at: float
    repository_path: Path
    focus_cwe_ids: list[str]
    result_submitted: bool
    submission_error: str | None = None
    consecutive_no_tool_turns: int = 0
    consecutive_duplicate_turns: int = 0
    trajectory: list[TrajectoryEntry] = field(default_factory=list)
    terminal_call_budget: int | None = None
    terminal_calls_used: int = 0
    post_budget_submission_attempts: int = 0
    generation_errors: int = 0


@dataclass(slots=True)
class TurnResult:
    """Result of a single model turn, importable by shell for inline rendering."""

    done: bool


@dataclass(slots=True)
class AgentRunResult:
    findings: list[Finding]
    summary: ReportSummary
    investigation_trace: Path
