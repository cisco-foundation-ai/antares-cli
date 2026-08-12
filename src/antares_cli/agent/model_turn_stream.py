# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Streaming and parsing for a single model turn."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from antares_cli.agent.contracts import BuildAgentStateFn, ProgressCallback
from antares_cli.agent.model_adapter import ModelAdapter
from antares_cli.agent.state import ModelSessionState
from antares_cli.agent.streaming import (
    ParsedAnswer,
    ParsedDoneSignal,
    ParsedTextChunk,
    ParsedToolCall,
)
from antares_cli.agent.transcript import (
    compact_transcript,
    hard_compact_transcript,
    prompt_token_budget,
)
from antares_cli.inference.backend import (
    InferenceBackend,
    InferenceContextLengthError,
    InferenceError,
    InferenceStreamError,
)
from antares_cli.output.finding import TrajectoryEntry

MAX_PARSE_RETRIES = 2
MAX_MODEL_TURN_CHARS = 1_000_000


def _http_error_message(error: httpx.HTTPError) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        if status_code == 401:
            return (
                "Inference endpoint authentication failed (HTTP 401). "
                "Check the configured credentials."
            )
        if status_code == 403:
            return "Inference endpoint denied access (HTTP 403). Check the configured permissions."
        return f"Inference endpoint request failed (HTTP {status_code})."
    return f"Could not reach the inference endpoint ({type(error).__name__})."


@dataclass(slots=True)
class StreamedTurnOutput:
    assistant_text: str
    tool_calls: list[ParsedToolCall]
    generation_error: bool = False


class ModelTurnStreamer:
    """Streams backend output and converts parser events into session mutations."""

    def __init__(
        self,
        *,
        inference_backend: InferenceBackend | None,
        adapter: ModelAdapter,
        build_agent_state: BuildAgentStateFn,
    ) -> None:
        self.inference_backend = inference_backend
        self.adapter = adapter
        self.build_agent_state = build_agent_state

    def parse_turn_with_retries(
        self,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None,
        retry_parse_errors: bool = True,
    ) -> StreamedTurnOutput:
        parsed_turn = StreamedTurnOutput(assistant_text="", tool_calls=[])
        for retry_index in range(MAX_PARSE_RETRIES + 1):
            parsed_turn, parse_error_in_turn = self._stream_single_attempt(
                state,
                progress_callback=progress_callback,
            )
            if parsed_turn.assistant_text:
                state.session_trace.record_message(
                    {"role": "assistant", "content": parsed_turn.assistant_text},
                    attempt=retry_index + 1,
                    parse_error=parse_error_in_turn,
                    generation_error=parsed_turn.generation_error,
                )
            if parsed_turn.generation_error:
                return parsed_turn
            if retry_parse_errors and self._should_retry_parse(
                parse_error_in_turn=parse_error_in_turn,
                parsed_turn=parsed_turn,
                retry_index=retry_index,
                state=state,
            ):
                continue
            break
        return parsed_turn

    def _stream_single_attempt(
        self,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None,
        allow_context_fallback: bool = True,
    ) -> tuple[StreamedTurnOutput, bool]:
        inference_backend = self.inference_backend
        if inference_backend is None:
            raise InferenceError("No inference backend is configured for this model turn.")
        assistant_chunks: list[str] = []
        assistant_char_count = 0
        tool_calls: list[ParsedToolCall] = []
        parse_error_in_turn = False
        state.output_parser = self.adapter.create_output_parser()
        self._compact_transcript(state)

        try:
            chunks = iter(inference_backend.stream_generate(state.messages))
        except InferenceContextLengthError:
            return self._retry_after_context_rejection(
                state,
                progress_callback=progress_callback,
                allow_context_fallback=allow_context_fallback,
            )
        except httpx.HTTPError as exc:
            raise InferenceError(_http_error_message(exc)) from exc
        except InferenceStreamError as exc:
            return self._stream_failure_output(
                state,
                exc,
                assistant_text="".join(assistant_chunks),
                tool_calls=tool_calls,
                parse_error_in_turn=parse_error_in_turn,
            )

        while True:
            try:
                chunk = next(chunks)
            except StopIteration:
                break
            except InferenceContextLengthError:
                if assistant_chunks:
                    raise
                return self._retry_after_context_rejection(
                    state,
                    progress_callback=progress_callback,
                    allow_context_fallback=allow_context_fallback,
                )
            except httpx.HTTPError as exc:
                raise InferenceError(_http_error_message(exc)) from exc
            except InferenceStreamError as exc:
                return self._stream_failure_output(
                    state,
                    exc,
                    assistant_text="".join(assistant_chunks),
                    tool_calls=tool_calls,
                    parse_error_in_turn=parse_error_in_turn,
                )
            assistant_char_count += len(chunk)
            if assistant_char_count > MAX_MODEL_TURN_CHARS:
                return self._stream_failure_output(
                    state,
                    InferenceStreamError("Inference response exceeded the model-turn size limit."),
                    assistant_text="".join(assistant_chunks),
                    tool_calls=tool_calls,
                    parse_error_in_turn=parse_error_in_turn,
                )
            assistant_chunks.append(chunk)
            for event in state.output_parser.feed(chunk):
                parse_error_in_turn = (
                    self._consume_stream_event(
                        event,
                        state,
                        tool_calls=tool_calls,
                        progress_callback=progress_callback,
                    )
                    or parse_error_in_turn
                )

        for event in state.output_parser.flush():
            parse_error_in_turn = (
                self._consume_flushed_event(event, state, tool_calls=tool_calls)
                or parse_error_in_turn
            )

        return StreamedTurnOutput(
            assistant_text="".join(assistant_chunks),
            tool_calls=tool_calls,
        ), parse_error_in_turn

    def _compact_transcript(
        self,
        state: ModelSessionState,
        *,
        hard_limit: bool = False,
    ) -> None:
        inference_backend = self.inference_backend
        if inference_backend is None:
            raise InferenceError("No inference backend is configured for transcript compaction.")
        reserved_output_tokens = getattr(inference_backend, "max_tokens", 4096)
        if isinstance(reserved_output_tokens, bool) or not isinstance(reserved_output_tokens, int):
            reserved_output_tokens = 4096
        compaction_function = hard_compact_transcript if hard_limit else compact_transcript
        compaction = compaction_function(
            state.messages,
            token_budget=prompt_token_budget(
                context_window=inference_backend.context_window,
                reserved_output_tokens=reserved_output_tokens,
            ),
        )
        if not compaction.changed:
            return
        state.messages[:] = compaction.messages
        state.session_trace.record_event(
            phase="context_compaction",
            payload={
                "before_tokens_estimate": compaction.before_tokens,
                "after_tokens_estimate": compaction.after_tokens,
                "removed_messages": compaction.removed_messages,
                "truncated_messages": compaction.truncated_messages,
                "strategy": "serialized_byte_bound" if hard_limit else "calibrated",
            },
        )

    def _retry_after_context_rejection(
        self,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None,
        allow_context_fallback: bool,
    ) -> tuple[StreamedTurnOutput, bool]:
        if not allow_context_fallback:
            raise InferenceContextLengthError(
                "Inference request exceeded the model context capacity after compaction."
            )
        self._compact_transcript(state, hard_limit=True)
        state.session_trace.record_event(
            phase="context_retry",
            payload={"strategy": "serialized_byte_bound"},
        )
        return self._stream_single_attempt(
            state,
            progress_callback=progress_callback,
            allow_context_fallback=False,
        )

    def _stream_failure_output(
        self,
        state: ModelSessionState,
        error: InferenceStreamError,
        *,
        assistant_text: str,
        tool_calls: list[ParsedToolCall],
        parse_error_in_turn: bool,
    ) -> tuple[StreamedTurnOutput, bool]:
        return StreamedTurnOutput(
            assistant_text=assistant_text,
            tool_calls=tool_calls,
            generation_error=True,
        ), parse_error_in_turn

    def _consume_stream_event(
        self,
        event: object,
        state: ModelSessionState,
        *,
        tool_calls: list[ParsedToolCall],
        progress_callback: ProgressCallback | None,
    ) -> bool:
        if isinstance(event, ParsedToolCall):
            tool_calls.append(event)
            self._publish_progress(state, progress_callback)
            return False
        if isinstance(event, ParsedDoneSignal):
            self._record_done_signal(state)
            return False
        if isinstance(event, ParsedAnswer):
            self._record_answer(event, state)
            return False
        if isinstance(event, ParsedTextChunk):
            return self._record_text_chunk(
                event,
                state,
                publish_progress=True,
                progress_callback=progress_callback,
            )
        return False

    def _consume_flushed_event(
        self,
        event: object,
        state: ModelSessionState,
        *,
        tool_calls: list[ParsedToolCall],
    ) -> bool:
        if isinstance(event, ParsedToolCall):
            tool_calls.append(event)
            return False
        if isinstance(event, ParsedDoneSignal):
            state.done_signaled = True
            return False
        if isinstance(event, ParsedAnswer):
            self._record_answer(event, state)
            return False
        if isinstance(event, ParsedTextChunk):
            return self._record_text_chunk(
                event,
                state,
                publish_progress=False,
                progress_callback=None,
            )
        return False

    def _record_done_signal(self, state: ModelSessionState) -> None:
        state.done_signaled = True
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="think",
                content="Investigation complete.",
            )
        )

    def _record_answer(self, event: ParsedAnswer, state: ModelSessionState) -> None:
        state.answer_text = self.adapter.clean_model_text(event.text)
        state.done_signaled = True

    def _record_text_chunk(
        self,
        event: ParsedTextChunk,
        state: ModelSessionState,
        *,
        publish_progress: bool,
        progress_callback: ProgressCallback | None,
    ) -> bool:
        parse_error_in_turn = event.text.startswith("parse error:")
        stripped_text = event.text.strip()
        if not stripped_text:
            return parse_error_in_turn
        state.reasoning_log.append(stripped_text)
        if publish_progress:
            state.trajectory.append(
                TrajectoryEntry(
                    entry_type="think",
                    content=stripped_text,
                )
            )
            self._publish_progress(state, progress_callback)
        return parse_error_in_turn

    @staticmethod
    def _should_retry_parse(
        *,
        parse_error_in_turn: bool,
        parsed_turn: StreamedTurnOutput,
        retry_index: int,
        state: ModelSessionState,
    ) -> bool:
        if not parse_error_in_turn or parsed_turn.tool_calls or state.done_signaled:
            return False
        if retry_index >= MAX_PARSE_RETRIES:
            return False
        state.retried_turns_count += 1
        state.reasoning_log.append(
            f"Parse retry {retry_index + 1}/{MAX_PARSE_RETRIES}: retrying model turn"
        )
        return True

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
