# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tool execution side effects for model-driven audits."""

from __future__ import annotations

from antares_cli.agent.contracts import BASH_TOOL_NAME, TERMINAL_TOOL_NAME
from antares_cli.agent.quarantine import validate_tool_call_safety
from antares_cli.agent.state import ModelSessionState
from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.agent.tool_router import ToolRouter, bound_tool_error
from antares_cli.output.finding import TrajectoryEntry
from antares_cli.tools.shell_exec import MAX_TOOL_OUTPUT_CHARS

REPOSITORY_COMMAND_TOOLS = {BASH_TOOL_NAME, TERMINAL_TOOL_NAME, "read_file"}


class AgentToolExecutor:
    """Executes model-requested tools and records all related session side effects."""

    def __init__(self, *, tool_router: ToolRouter) -> None:
        self.tool_router = tool_router

    def execute(self, parsed_call: ParsedToolCall, state: ModelSessionState) -> str:
        state.tool_call_count += 1
        self._record_tool_call(parsed_call, state)
        if parsed_call.tool_name in REPOSITORY_COMMAND_TOOLS:
            if self._terminal_budget_exhausted(state):
                state.failed_tool_calls_count += 1
                tool_response_text = self._record_budget_exhaustion(parsed_call.tool_name, state)
                self._record_trajectory(parsed_call, state, tool_response_text)
                return tool_response_text
            state.terminal_calls_used += 1

        safety_check = validate_tool_call_safety(
            parsed_call.tool_name,
            parsed_call.arguments,
            allowed_sensitive_files=self.tool_router.allowed_sensitive_files,
        )
        if not safety_check.safe:
            state.failed_tool_calls_count += 1
            tool_response_text = f"Tool call blocked: {safety_check.blocked_reason}"
            state.session_trace.record_event(
                phase="tool_blocked",
                payload={
                    "tool_name": parsed_call.tool_name,
                    "reason": safety_check.blocked_reason or "",
                },
            )
        else:
            tool_response_text = self._execute_safe_tool_call(parsed_call, state)

        self._record_trajectory(parsed_call, state, tool_response_text)
        return tool_response_text

    @staticmethod
    def _terminal_budget_exhausted(state: ModelSessionState) -> bool:
        budget = state.terminal_call_budget
        return budget is not None and state.terminal_calls_used >= budget

    @staticmethod
    def _record_budget_exhaustion(tool_name: str, state: ModelSessionState) -> str:
        budget = state.terminal_call_budget
        if budget is None:
            raise RuntimeError(
                "Repository tool budget exhaustion was recorded without a configured budget"
            )
        message = f"Terminal call budget exhausted ({budget}/{budget}). Submit your answer."
        state.session_trace.record_event(
            phase="tool_blocked",
            payload={"tool_name": tool_name, "reason": message},
        )
        state.session_trace.record_tool_result(
            tool_name=tool_name,
            result_summary=message,
            evidence_id="budget_exhausted",
        )
        return message

    def _record_tool_call(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
    ) -> None:
        state.session_trace.record_tool_call(
            tool_name=parsed_call.tool_name,
            arguments=parsed_call.arguments,
        )

    def _execute_safe_tool_call(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
    ) -> str:
        execution_result = self.tool_router.execute(
            parsed_call.tool_name,
            parsed_call.arguments,
        )
        if not execution_result.success:
            return self._record_tool_error(parsed_call, state, execution_result.error_message)
        state.consecutive_errors = 0
        tool_response_text = self._sanitize_tool_output(
            parsed_call,
            state,
            _format_tool_output(execution_result.output),
        )
        state.session_trace.record_tool_result(
            tool_name=parsed_call.tool_name,
            result_summary=tool_response_text[:500],
            evidence_id=state.session_trace.new_evidence_id(),
        )
        return tool_response_text

    def _record_tool_error(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
        error_message: str | None,
    ) -> str:
        state.failed_tool_calls_count += 1
        state.consecutive_errors += 1
        tool_response_text = bound_tool_error(
            f"Tool {parsed_call.tool_name} failed: {error_message}"
        )
        if state.consecutive_errors >= 2:
            available = ", ".join(self.tool_router.available_tool_names())
            tool_response_text = bound_tool_error(
                tool_response_text
                + f"\n\nAvailable tools: {available}. Use one of these exact names."
            )
        state.session_trace.record_tool_result(
            tool_name=parsed_call.tool_name,
            result_summary=tool_response_text,
            evidence_id="error",
        )
        return tool_response_text

    @staticmethod
    def _sanitize_tool_output(
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
        raw_output: str,
    ) -> str:
        scan_result = state.content_quarantine.scan(raw_output)
        if not scan_result.injection_detected:
            return scan_result.sanitized_text
        alert_source = _alert_source(parsed_call)
        state.session_trace.record_event(
            phase="quarantine_alert",
            payload={"source": alert_source, "count": len(scan_result.quarantined_spans)},
        )
        return scan_result.sanitized_text

    @staticmethod
    def _record_trajectory(
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
        tool_response_text: str,
    ) -> None:
        full_args = ", ".join(f"{key}={value}" for key, value in parsed_call.arguments.items())
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="tool_call",
                content=f"→ {parsed_call.tool_name}({full_args})",
            )
        )
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="tool_response",
                content=tool_response_text,
            )
        )


def _format_tool_output(output: object) -> str:
    """Format tool execution output for the model, surfacing truncation."""
    if not isinstance(output, dict):
        return str(output)
    stdout = output.get("stdout", "")
    stderr = output.get("stderr", "")
    truncated = output.get("truncated", False)
    result = str(stdout)
    if stderr:
        result += f"\n[stderr]: {stderr}"
    if truncated:
        result += (
            f"\n\n[OUTPUT TRUNCATED: showing first {MAX_TOOL_OUTPUT_CHARS:,} characters. "
            "Use head/tail/sed with line ranges to read specific sections.]"
        )
    return result


def _alert_source(parsed_call: ParsedToolCall) -> str:
    args_summary = ", ".join(
        f"{key}={str(value)[:30]}" for key, value in list(parsed_call.arguments.items())[:2]
    )
    return f"{parsed_call.tool_name}({args_summary})"
