# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Single-turn model execution for the Antares agent loop."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from antares_cli.agent.contracts import BuildAgentStateFn, ProgressCallback
from antares_cli.agent.model_adapter import ModelAdapter, ToolCallResult
from antares_cli.agent.model_turn_stream import ModelTurnStreamer
from antares_cli.agent.state import ModelSessionState, TurnResult
from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.inference.backend import InferenceBackend
from antares_cli.output.finding import Finding, TrajectoryEntry

MAX_POST_BUDGET_SUBMISSION_ATTEMPTS = 3


@dataclass(slots=True)
class _ToolExecutionResult:
    executed_tool_calls: list[ToolCallResult]
    submitted: bool = False
    all_duplicates: bool = False


class SubmitToolCallFn(Protocol):
    def __call__(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> list[Finding]: ...


class ModelTurnRunner:
    """Runs one model turn and translates streamed output into agent state changes."""

    def __init__(
        self,
        *,
        inference_backend: InferenceBackend | None,
        adapter: ModelAdapter,
        is_submit_tool_call: Callable[[ParsedToolCall], bool],
        execute_tool_call: Callable[[ParsedToolCall, ModelSessionState], str],
        handle_submit_tool_call: SubmitToolCallFn,
        build_agent_state: BuildAgentStateFn,
    ) -> None:
        self.adapter = adapter
        self.is_submit_tool_call = is_submit_tool_call
        self.execute_tool_call = execute_tool_call
        self.handle_submit_tool_call = handle_submit_tool_call
        self.build_agent_state = build_agent_state
        self.streamer = ModelTurnStreamer(
            inference_backend=inference_backend,
            adapter=adapter,
            build_agent_state=build_agent_state,
        )

    def run_turn(
        self,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None = None,
        iteration_index: int = 0,
        maximum_iterations: int,
    ) -> TurnResult:
        """Run one full model turn: stream, parse events, execute tools, update messages."""
        parsed_turn = self.streamer.parse_turn_with_retries(
            state,
            progress_callback=progress_callback,
            retry_parse_errors=not _is_terminal_budget_exhausted(state),
        )

        if parsed_turn.generation_error:
            state.generation_errors += 1
            state.reasoning_log.append(
                "Model generation error interrupted this run; results may be incomplete."
            )
            return TurnResult(done=True)

        if _is_terminal_budget_exhausted(state):
            tool_execution = self._execute_tool_calls(
                parsed_turn.tool_calls,
                state,
                progress_callback=progress_callback,
            )
            if tool_execution.submitted or state.done_signaled:
                return TurnResult(done=True)
            return self._handle_post_budget_submission_attempt(
                state,
                assistant_text=parsed_turn.assistant_text,
                executed_tool_calls=tool_execution.executed_tool_calls,
                progress_callback=progress_callback,
            )

        if not parsed_turn.tool_calls:
            return self._handle_no_tool_calls(
                state,
                assistant_text=parsed_turn.assistant_text,
            )

        state.consecutive_no_tool_turns = 0
        tool_execution = self._execute_tool_calls(
            parsed_turn.tool_calls,
            state,
            progress_callback=progress_callback,
        )
        if tool_execution.submitted:
            return TurnResult(done=True)

        if tool_execution.all_duplicates:
            return self._handle_duplicate_tool_turn(
                state,
                assistant_text=parsed_turn.assistant_text,
            )

        state.consecutive_duplicate_turns = 0
        return self._handle_tool_results(
            state,
            assistant_text=parsed_turn.assistant_text,
            executed_tool_calls=tool_execution.executed_tool_calls,
            iteration_index=iteration_index,
            maximum_iterations=maximum_iterations,
            progress_callback=progress_callback,
        )

    def _handle_no_tool_calls(
        self,
        state: ModelSessionState,
        *,
        assistant_text: str,
    ) -> TurnResult:
        remaining_text = self.adapter.clean_model_text(assistant_text)
        if remaining_text and not state.answer_text:
            state.answer_text = remaining_text
        retry_index = state.consecutive_no_tool_turns
        if retry_index < self.adapter.no_tool_retry_limit and not state.done_signaled:
            state.consecutive_no_tool_turns += 1
            state.messages.append({"role": "assistant", "content": assistant_text})
            _append_traced_message(
                state,
                self.adapter.format_no_tool_retry(iteration_index=retry_index),
            )
            return TurnResult(done=False)
        return TurnResult(done=True)

    def _execute_tool_calls(
        self,
        tool_calls: list[ParsedToolCall],
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None,
    ) -> _ToolExecutionResult:
        result = _ToolExecutionResult(executed_tool_calls=[], all_duplicates=True)
        for parsed_call in tool_calls:
            if self.is_submit_tool_call(parsed_call):
                self.handle_submit_tool_call(
                    parsed_call,
                    state,
                    progress_callback=progress_callback,
                )
                result.submitted = True
                return result
            if self._skip_duplicate_tool_call(parsed_call, state):
                continue
            result.all_duplicates = False
            result.executed_tool_calls.append(self._execute_tool_call(parsed_call, state))
        return result

    @staticmethod
    def _skip_duplicate_tool_call(
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
    ) -> bool:
        dedup_key = json.dumps(
            {"tool": parsed_call.tool_name, "args": parsed_call.arguments},
            sort_keys=True,
        )
        if dedup_key not in state.seen_tool_calls:
            state.seen_tool_calls.add(dedup_key)
            return False
        state.tool_call_count += 1
        state.failed_tool_calls_count += 1
        message = f"Skipped duplicate tool call: {parsed_call.tool_name}"
        state.reasoning_log.append(message)
        state.session_trace.record_tool_call(
            tool_name=parsed_call.tool_name,
            arguments=parsed_call.arguments,
        )
        state.session_trace.record_event(
            phase="tool_blocked",
            payload={"tool_name": parsed_call.tool_name, "reason": message},
        )
        state.session_trace.record_tool_result(
            tool_name=parsed_call.tool_name,
            result_summary=message,
            evidence_id="duplicate_tool_call",
        )
        return True

    def _execute_tool_call(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
    ) -> ToolCallResult:
        return ToolCallResult(
            tool_name=parsed_call.tool_name,
            tool_response=self.execute_tool_call(parsed_call, state),
        )

    def _handle_duplicate_tool_turn(
        self,
        state: ModelSessionState,
        *,
        assistant_text: str,
    ) -> TurnResult:
        state.consecutive_duplicate_turns += 1
        state.messages.append({"role": "assistant", "content": assistant_text})
        force_submit = state.consecutive_duplicate_turns >= 3
        _append_traced_message(
            state,
            self.adapter.format_duplicate_tool_retry(force_submit=force_submit),
        )
        if force_submit:
            state.reasoning_log.append(
                "Loop stuck: 3 consecutive duplicate turns - forcing submit."
            )
            state.trajectory.append(
                TrajectoryEntry(
                    entry_type="think",
                    content="Stuck loop detected - forcing transition to submission.",
                )
            )
        return TurnResult(done=False)

    def _handle_post_budget_submission_attempt(
        self,
        state: ModelSessionState,
        *,
        assistant_text: str,
        executed_tool_calls: list[ToolCallResult],
        progress_callback: ProgressCallback | None,
    ) -> TurnResult:
        state.post_budget_submission_attempts += 1
        state.messages.append({"role": "assistant", "content": assistant_text})
        if state.post_budget_submission_attempts >= MAX_POST_BUDGET_SUBMISSION_ATTEMPTS:
            return TurnResult(done=True)
        _append_traced_message(
            state,
            self.adapter.format_tool_results(
                executed_tool_calls,
                nudge_suffix=_submission_required_nudge(state),
            ),
        )
        self._publish_progress(state, progress_callback)
        return TurnResult(done=False)

    def _handle_tool_results(
        self,
        state: ModelSessionState,
        *,
        assistant_text: str,
        executed_tool_calls: list[ToolCallResult],
        iteration_index: int,
        maximum_iterations: int,
        progress_callback: ProgressCallback | None,
    ) -> TurnResult:
        if state.done_signaled:
            return TurnResult(done=True)
        state.messages.append({"role": "assistant", "content": assistant_text})
        nudge = _nudge_suffix(self.adapter, state, iteration_index, maximum_iterations)
        if _is_terminal_budget_exhausted(state):
            nudge = _submission_required_nudge(state)
        _append_traced_message(
            state,
            self.adapter.format_tool_results(executed_tool_calls, nudge_suffix=nudge),
        )
        self._publish_progress(state, progress_callback)
        return TurnResult(done=False)

    def _publish_progress(
        self,
        state: ModelSessionState,
        progress_callback: ProgressCallback | None,
    ) -> None:
        if progress_callback is None:
            return
        progress_callback(
            self.build_agent_state(
                messages=state.messages,
                trajectory=state.trajectory,
            ),
            None,
        )


def _nudge_suffix(
    adapter: ModelAdapter,
    state: ModelSessionState,
    iteration_index: int,
    maximum_iterations: int,
) -> str:
    budget_suffix = _terminal_budget_suffix(state)
    nudge_threshold = int(maximum_iterations * adapter.investigation_nudge_fraction)
    if iteration_index != nudge_threshold - 1:
        return budget_suffix
    state.trajectory.append(
        TrajectoryEntry(
            entry_type="think",
            content="Running low on turns - wrapping up investigation.",
        )
    )
    turn_nudge = (
        "\n\nYou are running low on remaining turns. "
        "Finish your investigation and submit file-level results now."
    )
    return turn_nudge + budget_suffix


def _terminal_budget_suffix(state: ModelSessionState) -> str:
    if state.terminal_call_budget is None:
        return ""
    remaining = state.terminal_call_budget - state.terminal_calls_used
    return f"\n[{remaining} tool-calls remaining]"


def _submission_required_nudge(state: ModelSessionState) -> str:
    budget = state.terminal_call_budget
    return (
        f"\nERROR: Repository tool budget exhausted ({budget}/{budget}). "
        "Submit now using either "
        '<tool_call>{"name":"submit_vulnerable_files","arguments":{"ranked_files":'
        '["path/to/file"]}}</tool_call> or '
        '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>.'
    )


def _is_terminal_budget_exhausted(state: ModelSessionState) -> bool:
    if state.terminal_call_budget is None:
        return False
    return state.terminal_calls_used >= state.terminal_call_budget


def _append_traced_message(
    state: ModelSessionState,
    message: dict[str, str],
) -> None:
    state.messages.append(message)
    state.session_trace.record_message(message)
