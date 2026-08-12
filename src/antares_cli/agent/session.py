# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Model session initialization for Antares audits."""

from __future__ import annotations

import time
from pathlib import Path

from antares_cli.agent.model_adapter import ModelAdapter
from antares_cli.agent.quarantine import ContentQuarantine
from antares_cli.agent.state import ModelSessionState
from antares_cli.agent.trace import SessionTrace
from antares_cli.inference.backend import InferenceBackend, InferenceError


class ModelSessionInitializer:
    """Builds the initial model session state and authoritative transcript."""

    def __init__(
        self,
        *,
        inference_backend: InferenceBackend | None,
        adapter: ModelAdapter,
    ) -> None:
        self.inference_backend = inference_backend
        self.adapter = adapter

    def initialize(
        self,
        repo_path: str | Path,
        *,
        user_query: str | None = None,
        focus_cwe_ids: list[str] | None = None,
        terminal_call_budget: int | None = None,
    ) -> ModelSessionState:
        """Set up prompts, tracing, and mutable state for model turns."""
        if self.inference_backend is None:
            raise InferenceError("No inference backend is configured for this model session.")
        repository_path = Path(repo_path).resolve()
        session_trace = SessionTrace(session_name=repository_path.name)
        content_quarantine = ContentQuarantine()

        session_trace.record_event(
            phase="ingest",
            payload={"path": str(repository_path), "query": user_query or ""},
        )
        initial_messages = self._initial_messages(
            user_query=user_query,
            focus_cwe_ids=focus_cwe_ids,
            terminal_call_budget=terminal_call_budget,
        )
        for message in initial_messages:
            session_trace.record_message(message)

        return ModelSessionState(
            findings=[],
            dedupe_keys=set(),
            reasoning_log=[],
            tool_call_count=0,
            messages=initial_messages,
            session_trace=session_trace,
            content_quarantine=content_quarantine,
            output_parser=self.adapter.create_output_parser(),
            done_signaled=False,
            answer_text="",
            consecutive_errors=0,
            retried_turns_count=0,
            failed_tool_calls_count=0,
            seen_tool_calls=set(),
            started_at=time.perf_counter(),
            repository_path=repository_path,
            focus_cwe_ids=list(focus_cwe_ids or []),
            result_submitted=False,
            submission_error=None,
            terminal_call_budget=terminal_call_budget,
        )

    def _initial_messages(
        self,
        *,
        user_query: str | None,
        focus_cwe_ids: list[str] | None,
        terminal_call_budget: int | None,
    ) -> list[dict[str, str]]:
        return self.adapter.format_initial_messages(
            system_prompt=self.adapter.build_system_prompt(
                terminal_call_budget=terminal_call_budget,
            ),
            user_content=self._initial_user_content(
                user_query=user_query,
                focus_cwe_ids=focus_cwe_ids,
            ),
        )

    def _initial_user_content(
        self,
        *,
        user_query: str | None,
        focus_cwe_ids: list[str] | None,
    ) -> str:
        return _default_task_description(user_query, focus_cwe_ids)


def _default_task_description(
    user_query: str | None,
    focus_cwe_ids: list[str] | None,
) -> str:
    if user_query:
        return user_query
    if focus_cwe_ids:
        cwe_list = ", ".join(focus_cwe_ids)
        return (
            f"Search this repository for vulnerabilities matching: {cwe_list}. "
            "Read source files, identify vulnerable code patterns, and submit "
            "ranked vulnerable file paths only."
        )
    return (
        "Search this repository for security vulnerabilities. Focus on: "
        "CWE-89 (SQL Injection), CWE-78 (Command Injection), CWE-79 (XSS), "
        "CWE-798 (Hardcoded Credentials), CWE-22 (Path Traversal), "
        "CWE-502 (Deserialization), CWE-306 (Missing Authentication). "
        "Read source files and submit ranked vulnerable file paths only."
    )
