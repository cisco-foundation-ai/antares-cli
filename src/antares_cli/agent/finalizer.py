# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Final result assembly for model-driven Antares audits."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from antares_cli.agent.model_adapter import ModelAdapter
from antares_cli.agent.state import AgentRunResult, ModelSessionState
from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.output.finding import Finding, ReportSummary


class AgentRunFinalizer:
    """Builds final reports and parses late submit calls from free text."""

    def __init__(
        self,
        *,
        adapter: ModelAdapter,
        is_submit_tool_call: Callable[[ParsedToolCall], bool],
        handle_submit_tool_call: Callable[[ParsedToolCall, ModelSessionState], list[Finding]],
    ) -> None:
        self.adapter = adapter
        self.is_submit_tool_call = is_submit_tool_call
        self.handle_submit_tool_call = handle_submit_tool_call

    def run_answer_parser_fallback(self, state: ModelSessionState) -> None:
        """Parse final submit tool calls from completed free text."""
        if state.result_submitted or state.submission_error is not None:
            return
        fallback_text = _fallback_text(state)
        if not fallback_text:
            return

        submit_calls = self.extract_submit_tool_calls(fallback_text)
        new_findings_count = 0
        for submit_call in submit_calls:
            new_findings_count += len(self.handle_submit_tool_call(submit_call, state))
            if state.result_submitted:
                break
        _record_submit_parser_result(state, submit_calls, new_findings_count)

    def extract_submit_tool_calls(self, text: str) -> list[ParsedToolCall]:
        return self.adapter.extract_submit_tool_calls(
            text,
            is_submit_tool_call=self.is_submit_tool_call,
        )

    def finalize(self, state: ModelSessionState) -> AgentRunResult:
        if not state.result_submitted and state.submission_error is None:
            self.run_answer_parser_fallback(state)
        investigation_trace = state.session_trace.finalize(summary_dict={})
        return AgentRunResult(
            findings=state.findings,
            summary=_summary_for_state(state, investigation_trace),
            investigation_trace=investigation_trace,
        )


def _fallback_text(state: ModelSessionState) -> str:
    if state.answer_text:
        return state.answer_text
    if state.findings:
        return ""
    return "\n".join(state.reasoning_log)


def _record_submit_parser_result(
    state: ModelSessionState,
    submit_calls: list[ParsedToolCall],
    new_findings_count: int,
) -> None:
    if submit_calls:
        state.reasoning_log.append(
            f"Submit parser: extracted {new_findings_count} file-level finding(s) from free text."
        )
    else:
        state.reasoning_log.append(
            "Submit parser: no submit tool calls found in free text; no findings extracted."
        )


def _summary_for_state(
    state: ModelSessionState,
    investigation_trace: Path,
) -> ReportSummary:
    return ReportSummary(
        total_findings=len(state.findings),
        tool_call_count=state.tool_call_count,
        duration_seconds=time.perf_counter() - state.started_at,
        investigation_trace=str(investigation_trace),
        cwe_ids_triggered=sorted(
            {cwe_id for finding in state.findings for cwe_id in finding.cwe_ids}
        ),
        failed_tool_calls=state.failed_tool_calls_count,
        retried_turns=state.retried_turns_count,
        generation_errors=state.generation_errors,
        incomplete_reason=(
            None
            if state.result_submitted
            else state.submission_error or "Model ended without an explicit final submission."
        ),
    )
