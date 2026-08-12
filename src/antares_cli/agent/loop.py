# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Core Antares agent loop with model-driven tool calling."""

from __future__ import annotations

from pathlib import Path

from antares_cli.agent.contracts import ProgressCallback, is_submit_tool_call
from antares_cli.agent.execution_policy import resolve_terminal_call_budget
from antares_cli.agent.finalizer import AgentRunFinalizer
from antares_cli.agent.model_adapter import (
    ModelAdapter,
    resolve_model_adapter,
)
from antares_cli.agent.model_turn import ModelTurnRunner
from antares_cli.agent.session import ModelSessionInitializer
from antares_cli.agent.state import AgentRunResult
from antares_cli.agent.submission import SubmissionHandler
from antares_cli.agent.tool_execution import AgentToolExecutor
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.agent.trace import attach_investigation_trace
from antares_cli.agent.transcript import estimate_transcript_tokens, prompt_token_budget
from antares_cli.inference.backend import InferenceBackend
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.output.finding import TrajectoryEntry
from antares_cli.output.renderer import AgentStateSnapshot

MAXIMUM_MODEL_LOOP_ITERATIONS = 50


class ModelBackendRequiredError(RuntimeError):
    """Raised when a model-driven audit is requested but no inference backend is available."""


class AntaresAgentLoop:
    """Runs the agent loop: initialize session, call model in a loop, finalize results."""

    def __init__(
        self,
        *,
        tool_router: ToolRouter,
        cwe_database: CweDatabase,
        inference_backend: InferenceBackend | None = None,
        model_label: str = "350M-dense",
        model_adapter: ModelAdapter | None = None,
    ) -> None:
        self.tool_router = tool_router
        self.cwe_database = cwe_database
        self.inference_backend = inference_backend
        self.adapter = model_adapter or resolve_model_adapter(model_label)

        self.tool_executor = AgentToolExecutor(tool_router=self.tool_router)
        self.submission_handler = SubmissionHandler(
            cwe_database=self.cwe_database,
            build_agent_state=self._build_agent_state,
            submission_root=self.tool_router.execution_root,
        )
        self.finalizer = AgentRunFinalizer(
            adapter=self.adapter,
            is_submit_tool_call=is_submit_tool_call,
            handle_submit_tool_call=self.submission_handler.handle,
        )
        self.session_initializer = ModelSessionInitializer(
            inference_backend=self.inference_backend,
            adapter=self.adapter,
        )
        self.turn_runner = ModelTurnRunner(
            inference_backend=self.inference_backend,
            adapter=self.adapter,
            is_submit_tool_call=is_submit_tool_call,
            execute_tool_call=self.tool_executor.execute,
            handle_submit_tool_call=self.submission_handler.handle,
            build_agent_state=self._build_agent_state,
        )

    def run_audit(
        self,
        repo_path: str | Path,
        *,
        user_query: str | None = None,
        focus_cwe_ids: list[str] | None = None,
        progress_callback: ProgressCallback | None = None,
        terminal_call_budget: int | None = None,
    ) -> AgentRunResult:
        if self.inference_backend is None:
            raise ModelBackendRequiredError(
                "No inference backend is available for model-driven audit. "
                "Provide model weights or configure a remote endpoint/API key."
            )

        resolved_terminal_call_budget = resolve_terminal_call_budget(terminal_call_budget)
        state = self.session_initializer.initialize(
            repo_path,
            user_query=user_query,
            focus_cwe_ids=focus_cwe_ids,
            terminal_call_budget=resolved_terminal_call_budget,
        )

        try:
            for iteration_index in range(MAXIMUM_MODEL_LOOP_ITERATIONS):
                turn_result = self.turn_runner.run_turn(
                    state,
                    progress_callback=progress_callback,
                    iteration_index=iteration_index,
                    maximum_iterations=MAXIMUM_MODEL_LOOP_ITERATIONS,
                )
                if turn_result.done:
                    break

            return self.finalizer.finalize(state)
        except BaseException as error:
            try:
                trace_path = state.session_trace.finalize_error(error)
            except BaseException:
                state.session_trace.close()
            else:
                attach_investigation_trace(error, trace_path)
            raise

    def _build_agent_state(
        self,
        *,
        messages: list[dict[str, str]] | None = None,
        trajectory: list[TrajectoryEntry] | None = None,
    ) -> AgentStateSnapshot:
        return AgentStateSnapshot(
            context_usage_percent=self._transcript_usage_percent(messages or []),
            trajectory=list(trajectory or []),
        )

    def _transcript_usage_percent(self, messages: list[dict[str, str]]) -> int:
        if self.inference_backend is None or not messages:
            return 0
        reserved_output_tokens = getattr(self.inference_backend, "max_tokens", 4096)
        if isinstance(reserved_output_tokens, bool) or not isinstance(reserved_output_tokens, int):
            reserved_output_tokens = 4096
        token_budget = prompt_token_budget(
            context_window=self.inference_backend.context_window,
            reserved_output_tokens=reserved_output_tokens,
        )
        used_tokens = estimate_transcript_tokens(messages)
        return min(100, int((used_tokens / token_budget) * 100))
