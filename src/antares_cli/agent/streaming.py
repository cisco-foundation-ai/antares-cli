# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Streaming parser for Antares tool-call markup."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_UNCLOSED_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*)", re.DOTALL)
_FRAMING_TOKENS = (
    "<|end_of_text|>",
    "<|endoftext|>",
    "<|eot_id|>",
    "<think>",
    "</think>",
)
_EOS_TOKENS = re.compile(r"<\|end_of_text\|>|<\|endoftext\|>|<\|eot_id\|>")
_THINK_TAGS = re.compile(r"</?think>")
_WRAPPED_OPEN_TAGS = {
    "tool_call": "<tool_call>",
    "done": "<done>",
    "answer": "<answer>",
}
_MAX_RECOVERY_CANDIDATES = 256
_MAX_RECOVERY_TEXT_LENGTH = 131_072


def _lenient_json_loads(raw: str) -> dict[str, Any] | None:
    """Parse JSON, tolerating extra trailing braces or concatenated objects."""
    text = raw.strip()
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass

    decoder = json.JSONDecoder()
    try:
        result, _ = decoder.raw_decode(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass

    for _ in range(3):
        if not text.endswith("}"):
            break
        text = text[:-1].rstrip()
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError, RecursionError):
            continue
    return None


@dataclass(frozen=True, slots=True)
class ParsedTextChunk:
    text: str


@dataclass(frozen=True, slots=True)
class ParsedToolCall:
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ParsedDoneSignal:
    pass


@dataclass(frozen=True, slots=True)
class ParsedAnswer:
    text: str


ParsedEvent = ParsedTextChunk | ParsedToolCall | ParsedDoneSignal | ParsedAnswer


def _tool_call_arguments(payload: dict[str, Any]) -> object:
    if "args" in payload:
        return payload["args"]
    if "arguments" in payload:
        return payload["arguments"]
    tool_name = payload.get("tool") or payload.get("name")
    if tool_name == "submit_no_vulnerability_found":
        return {}
    return None


def _is_tool_call_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    tool_name = payload.get("tool") or payload.get("name")
    arguments = _tool_call_arguments(payload)
    return isinstance(tool_name, str) and isinstance(arguments, dict)


def _build_tool_call(payload: dict[str, Any]) -> ParsedEvent:
    tool_name = payload.get("tool") or payload.get("name")
    arguments = _tool_call_arguments(payload)
    if not isinstance(tool_name, str):
        return ParsedTextChunk(text="parse error: tool_call missing 'tool'/'name' (str)")
    if not isinstance(arguments, dict):
        return ParsedTextChunk(text="parse error: tool_call missing 'args'/'arguments' (dict)")
    normalized_tool_name = re.sub(r"[\s-]+", "_", tool_name.strip().lower())
    return ParsedToolCall(tool_name=normalized_tool_name, arguments=arguments)


def _build_done_signal(_payload: dict[str, Any]) -> ParsedEvent:
    return ParsedDoneSignal()


_TAG_BUILDERS: dict[str, Callable[[dict[str, Any]], ParsedEvent]] = {
    "tool_call": _build_tool_call,
    "done": _build_done_signal,
}


class StreamingToolCallParser:
    """Parse wrapped or raw JSON tool calls without mutating JSON strings."""

    def __init__(self, *, recover_structured_suffix: bool = True) -> None:
        self._buffer = ""
        self._raw_candidate_active = False
        self._raw_decode_may_complete = False
        self._recover_structured_suffix = recover_structured_suffix

    def feed(self, text_chunk: str) -> list[ParsedEvent]:
        self._buffer += text_chunk
        if self._raw_candidate_active and "}" in text_chunk:
            self._raw_decode_may_complete = True
        events: list[ParsedEvent] = []
        while self._consume_next_event(events):
            pass
        self._emit_streamable_plain_text(events)
        return events

    def _consume_next_event(self, events: list[ParsedEvent]) -> bool:
        wrapped_tag = _next_wrapped_open_tag(self._buffer)
        raw_start = _next_raw_object_start(self._buffer)
        if raw_start is not None and (wrapped_tag is None or raw_start < wrapped_tag[1]):
            return self._consume_raw_object(events, raw_start)
        if wrapped_tag is not None:
            tag_name, tag_start = wrapped_tag
            return self._consume_wrapped_event(events, tag_name, tag_start)
        return False

    def _consume_raw_object(self, events: list[ParsedEvent], object_start: int) -> bool:
        if object_start > 0:
            _append_plain_text(events, self._buffer[:object_start])
            self._buffer = self._buffer[object_start:]
            self._raw_candidate_active = True
            self._raw_decode_may_complete = "}" in self._buffer
            return True

        if not self._raw_candidate_active:
            self._raw_candidate_active = True
            self._raw_decode_may_complete = "}" in self._buffer
        if _raw_object_prefix_is_invalid(self._buffer):
            _append_plain_text(events, self._buffer[0])
            self._buffer = self._buffer[1:]
            self._raw_candidate_active = False
            self._raw_decode_may_complete = False
            return True
        if not self._raw_decode_may_complete:
            return False
        self._raw_decode_may_complete = False

        try:
            payload, object_end = json.JSONDecoder().raw_decode(self._buffer)
        except (json.JSONDecodeError, ValueError, RecursionError):
            complete_end = _balanced_json_object_end(self._buffer)
            if complete_end is not None:
                _append_plain_text(events, self._buffer[:complete_end])
                self._buffer = self._buffer[complete_end:]
                self._raw_candidate_active = False
                return True
            return False

        if _is_tool_call_payload(payload):
            events.append(_build_tool_call(payload))
        else:
            _append_plain_text(events, self._buffer[:object_end])
        self._buffer = self._buffer[object_end:]
        self._raw_candidate_active = False
        return True

    def _consume_wrapped_event(
        self,
        events: list[ParsedEvent],
        tag_name: str,
        tag_start: int,
    ) -> bool:
        if tag_start > 0:
            _append_plain_text(events, self._buffer[:tag_start])
            self._buffer = self._buffer[tag_start:]
            return True

        opening_tag = _WRAPPED_OPEN_TAGS[tag_name]
        content_start = len(opening_tag)
        closing_tag = f"</{tag_name}>"
        if tag_name == "answer":
            closing_start = self._buffer.find(closing_tag, content_start)
            if closing_start < 0:
                return False
            answer_text = self._buffer[content_start:closing_start].strip()
            events.append(ParsedAnswer(text=answer_text))
            self._buffer = self._buffer[closing_start + len(closing_tag) :]
            return True

        json_start = content_start
        while json_start < len(self._buffer) and self._buffer[json_start].isspace():
            json_start += 1
        if json_start >= len(self._buffer):
            return False

        try:
            payload, relative_end = json.JSONDecoder().raw_decode(self._buffer[json_start:])
        except (json.JSONDecodeError, ValueError, RecursionError):
            return self._consume_invalid_or_lenient_wrapped_event(
                events,
                tag_name=tag_name,
                content_start=content_start,
                closing_tag=closing_tag,
            )

        json_end = json_start + relative_end
        closing_start = json_end
        while closing_start < len(self._buffer) and self._buffer[closing_start].isspace():
            closing_start += 1
        if self._buffer.startswith(closing_tag, closing_start):
            events.append(_build_wrapped_payload(tag_name, payload))
            self._buffer = self._buffer[closing_start + len(closing_tag) :]
            return True

        later_closing_start = self._buffer.find(closing_tag, json_end)
        if later_closing_start < 0:
            return False
        return self._consume_lenient_wrapped_payload(
            events,
            tag_name=tag_name,
            content_start=content_start,
            closing_start=later_closing_start,
            closing_tag=closing_tag,
        )

    def _consume_invalid_or_lenient_wrapped_event(
        self,
        events: list[ParsedEvent],
        *,
        tag_name: str,
        content_start: int,
        closing_tag: str,
    ) -> bool:
        closing_start = self._buffer.find(closing_tag, content_start)
        if closing_start < 0:
            return False
        return self._consume_lenient_wrapped_payload(
            events,
            tag_name=tag_name,
            content_start=content_start,
            closing_start=closing_start,
            closing_tag=closing_tag,
        )

    def _consume_lenient_wrapped_payload(
        self,
        events: list[ParsedEvent],
        *,
        tag_name: str,
        content_start: int,
        closing_start: int,
        closing_tag: str,
    ) -> bool:
        payload = _lenient_json_loads(self._buffer[content_start:closing_start])
        if payload is None:
            events.append(ParsedTextChunk(text=f"parse error: invalid JSON in <{tag_name}>"))
        else:
            events.append(_build_wrapped_payload(tag_name, payload))
        self._buffer = self._buffer[closing_start + len(closing_tag) :]
        return True

    def flush(self) -> list[ParsedEvent]:
        events: list[ParsedEvent] = []
        while self._consume_next_event(events):
            pass
        if not self._buffer:
            return events

        remaining_text = self._buffer
        self._buffer = ""
        self._raw_candidate_active = False
        self._raw_decode_may_complete = False
        recovered_suffix = (
            _recover_structured_suffix(remaining_text) if self._recover_structured_suffix else None
        )
        if recovered_suffix is not None:
            recovery_start, recovered_events = recovered_suffix
            _append_plain_text(events, remaining_text[:recovery_start])
            events.extend(recovered_events)
            return events
        unclosed_match = _UNCLOSED_TOOL_CALL_PATTERN.search(remaining_text)
        if unclosed_match:
            payload = _lenient_json_loads(unclosed_match.group(1))
            if payload is not None and _is_tool_call_payload(payload):
                _append_plain_text(events, remaining_text[: unclosed_match.start()])
                events.append(_build_tool_call(payload))
                return events
        _append_plain_text(events, remaining_text)
        return events

    def _emit_streamable_plain_text(self, events: list[ParsedEvent]) -> None:
        if self._raw_candidate_active or _next_wrapped_open_tag(self._buffer) is not None:
            return
        if _next_raw_object_start(self._buffer) is not None or len(self._buffer) <= 512:
            return
        safe_cutoff = _safe_plain_text_cutoff(self._buffer, len(self._buffer) - 256)
        if safe_cutoff == 0:
            return
        safe_text = self._buffer[:safe_cutoff]
        self._buffer = self._buffer[safe_cutoff:]
        _append_plain_text(events, safe_text)


def _next_wrapped_open_tag(text: str) -> tuple[str, int] | None:
    matches = [
        (tag_name, position)
        for tag_name, opening_tag in _WRAPPED_OPEN_TAGS.items()
        if (position := text.find(opening_tag)) >= 0
    ]
    return min(matches, key=lambda entry: entry[1]) if matches else None


def _next_raw_object_start(text: str) -> int | None:
    search_start = 0
    while (candidate_start := text.find("{", search_start)) >= 0:
        index = candidate_start + 1
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text) or text[index] in {'"', "}"}:
            return candidate_start
        search_start = candidate_start + 1
    return None


def _recover_structured_suffix(text: str) -> tuple[int, list[ParsedEvent]] | None:
    """Recover a later valid event after malformed model output.

    Recovery parsers deliberately cannot recurse back into this function.  The
    bounded tail and candidate count also keep malformed model output from
    turning end-of-stream recovery into unbounded work.
    """
    recovery_offset = max(0, len(text) - _MAX_RECOVERY_TEXT_LENGTH)
    recovery_text = text[recovery_offset:]
    candidate_starts = {
        position
        for opening_tag in _WRAPPED_OPEN_TAGS.values()
        for position in _all_substring_positions(recovery_text, opening_tag)
        if position > 0
    }
    candidate_starts.update(
        position for position in _all_raw_object_starts(recovery_text) if position > 0
    )
    ordered_candidates = sorted(candidate_starts)[-_MAX_RECOVERY_CANDIDATES:]
    for candidate_start in ordered_candidates:
        parser = StreamingToolCallParser(recover_structured_suffix=False)
        recovered_events = parser.feed(recovery_text[candidate_start:])
        recovered_events.extend(parser.flush())
        if any(not isinstance(event, ParsedTextChunk) for event in recovered_events):
            return recovery_offset + candidate_start, recovered_events
    return None


def _all_substring_positions(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    search_start = 0
    while (position := text.find(needle, search_start)) >= 0:
        positions.append(position)
        search_start = position + 1
    return positions


def _all_raw_object_starts(text: str) -> list[int]:
    starts: list[int] = []
    search_start = 0
    while search_start < len(text):
        relative_start = _next_raw_object_start(text[search_start:])
        if relative_start is None:
            break
        absolute_start = search_start + relative_start
        starts.append(absolute_start)
        search_start = absolute_start + 1
    return starts


def _build_wrapped_payload(tag_name: str, payload: object) -> ParsedEvent:
    if not isinstance(payload, dict):
        return ParsedTextChunk(text=f"parse error: invalid JSON object in <{tag_name}>")
    return _TAG_BUILDERS[tag_name](payload)


def _append_plain_text(events: list[ParsedEvent], text: str) -> None:
    cleaned = _THINK_TAGS.sub("", _EOS_TOKENS.sub("", text))
    if cleaned:
        events.append(ParsedTextChunk(text=cleaned))


def _raw_object_prefix_is_invalid(text: str) -> bool:
    index = 1
    while index < len(text) and text[index].isspace():
        index += 1
    return index < len(text) and text[index] not in {'"', "}"}


def _balanced_json_object_end(text: str) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index, character in enumerate(text):
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
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _safe_plain_text_cutoff(text: str, requested_cutoff: int) -> int:
    """Move a streaming boundary before any framing token it would split."""
    earliest_start = max(0, requested_cutoff - max(map(len, _FRAMING_TOKENS)) + 1)
    for token_start in range(earliest_start, requested_cutoff):
        for token in _FRAMING_TOKENS:
            if token_start < requested_cutoff < token_start + len(token) and text.startswith(
                token, token_start
            ):
                return token_start
    return requested_cutoff
