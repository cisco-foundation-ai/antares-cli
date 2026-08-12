# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the streaming tool-call parser with typed events."""

from __future__ import annotations

import json

import pytest

from antares_cli.agent.streaming import (
    ParsedAnswer,
    ParsedDoneSignal,
    ParsedTextChunk,
    ParsedToolCall,
    StreamingToolCallParser,
)


def test_plain_text_emitted_as_text_chunk_on_flush() -> None:
    parser = StreamingToolCallParser()
    parser.feed("hello world")
    events = parser.flush()

    assert len(events) == 1
    assert isinstance(events[0], ParsedTextChunk)
    assert events[0].text == "hello world"


def test_long_plain_reasoning_is_streamed_before_flush() -> None:
    parser = StreamingToolCallParser()

    events = parser.feed("reasoning " * 80)

    assert events
    assert all(isinstance(event, ParsedTextChunk) for event in events)
    assert "".join(event.text for event in events) in "reasoning " * 80


@pytest.mark.parametrize(
    "marker",
    ["<think>", "</think>", "<|end_of_text|>", "<|endoftext|>", "<|eot_id|>"],
)
def test_plain_text_framing_cleanup_is_chunk_invariant(marker: str) -> None:
    text = ("a" * 341) + marker + ("b" * 251)

    whole_parser = StreamingToolCallParser()
    whole_events = whole_parser.feed(text)
    whole_events.extend(whole_parser.flush())

    chunked_parser = StreamingToolCallParser()
    chunked_events = chunked_parser.feed(text[:550])
    chunked_events.extend(chunked_parser.feed(text[550:]))
    chunked_events.extend(chunked_parser.flush())

    whole_text = "".join(event.text for event in whole_events if isinstance(event, ParsedTextChunk))
    chunked_text = "".join(
        event.text for event in chunked_events if isinstance(event, ParsedTextChunk)
    )
    assert marker not in whole_text
    assert whole_text == chunked_text == ("a" * 341) + ("b" * 251)


def test_tool_call_parsed_correctly() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"tool": "bash", "args": {"command": "cat app.py"}})
    events = parser.feed(f"<tool_call>\n{payload}\n</tool_call>")

    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ParsedToolCall)
    assert event.tool_name == "bash"
    assert event.arguments == {"command": "cat app.py"}


def test_submit_tool_call_parsed_correctly() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps(
        {
            "name": "submit_vulnerable_files",
            "arguments": {"ranked_files": ["app.py", "settings.py"]},
        }
    )
    events = parser.feed(f"<tool_call>\n{payload}\n</tool_call>")

    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ParsedToolCall)
    assert event.tool_name == "submit_vulnerable_files"
    assert event.arguments == {"ranked_files": ["app.py", "settings.py"]}


def test_empty_args_alias_is_preserved_in_wrapped_tool_call() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"name": "submit_no_vulnerability_found", "args": {}})

    events = parser.feed(f"<tool_call>{payload}</tool_call>")

    assert events == [ParsedToolCall(tool_name="submit_no_vulnerability_found", arguments={})]


def test_missing_arguments_are_accepted_for_zero_argument_submission() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"name": "submit_no_vulnerability_found"})

    events = parser.feed(f"<tool_call>{payload}</tool_call>")

    assert events == [ParsedToolCall(tool_name="submit_no_vulnerability_found", arguments={})]


def test_raw_json_submit_tool_call_parsed_on_flush() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps(
        {
            "name": "submit_vulnerable_files",
            "arguments": {"ranked_files": ["app.py"]},
        }
    )
    events = parser.feed(f"Final answer:\n{payload}\n")
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert len(tool_calls) == 1
    assert tool_calls[0].tool_name == "submit_vulnerable_files"
    assert tool_calls[0].arguments == {"ranked_files": ["app.py"]}


def test_empty_args_alias_is_preserved_in_raw_tool_call() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"name": "submit_no_vulnerability_found", "args": {}})
    events = parser.feed(payload)
    events.extend(parser.flush())

    assert events == [ParsedToolCall(tool_name="submit_no_vulnerability_found", arguments={})]


def test_long_raw_terminal_call_survives_chunked_streaming() -> None:
    parser = StreamingToolCallParser()
    command = "echo " + ("x" * 700)
    payload = json.dumps({"name": "terminal", "arguments": {"command": command}})
    events = []

    for start in range(0, len(payload), 37):
        events.extend(parser.feed(payload[start : start + 37]))
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert tool_calls == [ParsedToolCall(tool_name="terminal", arguments={"command": command})]


def test_long_raw_submit_call_survives_chunked_streaming() -> None:
    parser = StreamingToolCallParser()
    ranked_files = [f"src/generated/file-{index:03}.py" for index in range(40)]
    payload = json.dumps(
        {
            "name": "submit_vulnerable_files",
            "arguments": {"ranked_files": ranked_files},
        }
    )
    events = []

    for start in range(0, len(payload), 41):
        events.extend(parser.feed(payload[start : start + 41]))
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert tool_calls == [
        ParsedToolCall(
            tool_name="submit_vulnerable_files",
            arguments={"ranked_files": ranked_files},
        )
    ]


def test_raw_tool_call_before_tagged_tool_call_is_not_lost() -> None:
    parser = StreamingToolCallParser()
    raw_call = json.dumps({"name": "terminal", "arguments": {"command": "ls"}})
    tagged_call = '<tool_call>{"name":"terminal","arguments":{"command":"pwd"}}</tool_call>'

    events = parser.feed(raw_call + tagged_call)
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert tool_calls == [
        ParsedToolCall(tool_name="terminal", arguments={"command": "ls"}),
        ParsedToolCall(tool_name="terminal", arguments={"command": "pwd"}),
    ]


def test_consecutive_long_raw_calls_retain_incomplete_suffix_across_chunks() -> None:
    parser = StreamingToolCallParser()
    first_command = "echo " + ("a" * 700)
    first_call = json.dumps({"name": "terminal", "arguments": {"command": first_command}})
    long_path = "src/" + ("b" * 700) + ".py"
    second_call = json.dumps(
        {
            "name": "submit_vulnerable_files",
            "arguments": {"ranked_files": [long_path]},
        }
    )
    second_string_start = second_call.index("src/") + 100
    events = parser.feed(first_call + second_call[:second_string_start])
    events.extend(parser.feed(second_call[second_string_start:-2]))
    events.extend(parser.feed(second_call[-2:]))
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert tool_calls == [
        ParsedToolCall(tool_name="terminal", arguments={"command": first_command}),
        ParsedToolCall(
            tool_name="submit_vulnerable_files",
            arguments={"ranked_files": [long_path]},
        ),
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"arguments": {"command": "x" * 900}, "name": "terminal"},
        {"name": "terminal", "metadata": "x" * 900, "arguments": {"command": "pwd"}},
    ],
)
def test_long_raw_tool_call_parsing_is_independent_of_key_order_and_distance(
    payload: dict[str, object],
) -> None:
    parser = StreamingToolCallParser()
    serialized = json.dumps(payload)
    events = []

    for start in range(0, len(serialized), 43):
        events.extend(parser.feed(serialized[start : start + 43]))
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    assert len(tool_calls) == 1
    assert tool_calls[0].tool_name == "terminal"
    assert tool_calls[0].arguments == payload["arguments"]


@pytest.mark.parametrize(
    "command",
    [
        "rg '<think>' .",
        "rg '</think>' .",
        "rg '<|end_of_text|>' .",
        "rg '<|endoftext|>' .",
        "rg '<|eot_id|>' .",
    ],
)
def test_model_framing_tokens_inside_arguments_are_not_mutated(command: str) -> None:
    payload = json.dumps({"name": "terminal", "arguments": {"command": command}})
    wrapped = f"<tool_call>{payload}</tool_call>"

    whole_events = StreamingToolCallParser().feed(wrapped)
    chunked_parser = StreamingToolCallParser()
    chunked_events = []
    for character in wrapped:
        chunked_events.extend(chunked_parser.feed(character))
    chunked_events.extend(chunked_parser.flush())

    expected = [ParsedToolCall(tool_name="terminal", arguments={"command": command})]
    assert whole_events == expected
    assert chunked_events == expected


def test_wrapped_tool_call_ignores_closing_tag_text_inside_json_string() -> None:
    parser = StreamingToolCallParser()
    command = "rg '}</tool_call>' ."
    payload = json.dumps({"name": "terminal", "arguments": {"command": command}})

    events = parser.feed(f"<tool_call>{payload}</tool_call>")

    assert events == [ParsedToolCall(tool_name="terminal", arguments={"command": command})]


@pytest.mark.parametrize("marker", ["<answer>fake</answer>", "<done>{}</done>"])
def test_raw_tool_call_ignores_protocol_tags_inside_json_string(marker: str) -> None:
    parser = StreamingToolCallParser()
    command = f"rg '{marker}' ."
    payload = json.dumps({"name": "terminal", "arguments": {"command": command}})

    events = parser.feed(payload)
    events.extend(parser.flush())

    assert events == [ParsedToolCall(tool_name="terminal", arguments={"command": command})]


@pytest.mark.parametrize(
    ("trailing_protocol", "expected_type"),
    [
        ("<done>{}</done>", ParsedDoneSignal),
        ("<answer>finished</answer>", ParsedAnswer),
    ],
)
def test_long_raw_call_preserves_following_chunked_protocol_event(
    trailing_protocol: str,
    expected_type: type[ParsedDoneSignal] | type[ParsedAnswer],
) -> None:
    parser = StreamingToolCallParser()
    command = "echo " + ("x" * 700)
    raw_call = json.dumps({"name": "terminal", "arguments": {"command": command}})
    combined = raw_call + trailing_protocol
    events = []

    for start in range(0, len(combined), 17):
        events.extend(parser.feed(combined[start : start + 17]))
    events.extend(parser.flush())

    assert isinstance(events[0], ParsedToolCall)
    assert any(isinstance(event, expected_type) for event in events[1:])


@pytest.mark.parametrize("include_tagged_call", [False, True])
def test_malformed_json_prefix_does_not_hide_later_valid_submission(
    include_tagged_call: bool,
) -> None:
    parser = StreamingToolCallParser()
    malformed_prefix = 'analysis {"unfinished":"'
    tagged_call = (
        '<tool_call>{"name":"terminal","arguments":{"command":"pwd"}}</tool_call>'
        if include_tagged_call
        else ""
    )
    raw_submit = json.dumps({"name": "submit_no_vulnerability_found", "arguments": {}})

    events = parser.feed(malformed_prefix + tagged_call + raw_submit)
    events.extend(parser.flush())

    tool_calls = [event for event in events if isinstance(event, ParsedToolCall)]
    expected_names = (
        ["terminal", "submit_no_vulnerability_found"]
        if include_tagged_call
        else ["submit_no_vulnerability_found"]
    )
    assert [tool_call.tool_name for tool_call in tool_calls] == expected_names


def test_done_signal_parsed_correctly() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"total_findings": 3, "tool_call_count": 5})
    events = parser.feed(f"<done>\n{payload}\n</done>")

    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ParsedDoneSignal)


def test_text_before_tool_call_emitted_separately() -> None:
    parser = StreamingToolCallParser()
    payload = json.dumps({"tool": "bash", "args": {"command": "tree -L 2"}})
    events = parser.feed(f"Analyzing project...\n<tool_call>\n{payload}\n</tool_call>")

    assert len(events) == 2
    assert isinstance(events[0], ParsedTextChunk)
    assert "Analyzing project..." in events[0].text
    assert isinstance(events[1], ParsedToolCall)
    assert events[1].tool_name == "bash"


def test_multiple_events_in_single_feed() -> None:
    parser = StreamingToolCallParser()
    tool_payload = json.dumps({"tool": "bash", "args": {"command": "cat a.py"}})
    done_payload = json.dumps({"total_findings": 0, "tool_call_count": 1})
    chunk = f"<tool_call>\n{tool_payload}\n</tool_call><done>\n{done_payload}\n</done>"
    events = parser.feed(chunk)

    assert len(events) == 2
    assert isinstance(events[0], ParsedToolCall)
    assert isinstance(events[1], ParsedDoneSignal)


def test_incremental_feeding_across_chunks() -> None:
    parser = StreamingToolCallParser()
    full_text = '<tool_call>\n{"tool": "bash", "args": {"command": "cat x.py"}}\n</tool_call>'

    all_events = []
    for character in full_text:
        all_events.extend(parser.feed(character))
    all_events.extend(parser.flush())

    tool_call_events = [e for e in all_events if isinstance(e, ParsedToolCall)]
    assert len(tool_call_events) == 1
    assert tool_call_events[0].tool_name == "bash"


def test_invalid_json_emits_text_chunk() -> None:
    parser = StreamingToolCallParser()
    events = parser.feed("<tool_call>\n{not valid json}\n</tool_call>")

    assert len(events) == 1
    assert isinstance(events[0], ParsedTextChunk)
    assert "parse error" in events[0].text


@pytest.mark.parametrize(
    "malformed_payload",
    [
        '{"name":"terminal","arguments":{"x":' + ("9" * 5_000) + "}}",
        '{"name":"terminal","arguments":{"x":' + ("[" * 10_000) + ("[]" * 10_000) + "}}",
    ],
)
@pytest.mark.parametrize("wrapped", [False, True])
def test_malformed_extreme_json_never_escapes_parser(
    malformed_payload: str,
    wrapped: bool,
) -> None:
    parser = StreamingToolCallParser()
    text = f"<tool_call>{malformed_payload}</tool_call>" if wrapped else malformed_payload

    events = parser.feed(text)
    events.extend(parser.flush())

    assert events
    assert not any(isinstance(event, ParsedToolCall) for event in events)


def test_flush_empty_buffer_returns_empty_list() -> None:
    parser = StreamingToolCallParser()
    assert parser.flush() == []


def test_missing_tool_name_in_tool_call_emits_error() -> None:
    parser = StreamingToolCallParser()
    events = parser.feed('<tool_call>\n{"args": {"command": "ls"}}\n</tool_call>')

    assert len(events) == 1
    assert isinstance(events[0], ParsedTextChunk)
    assert "parse error" in events[0].text
    assert "tool" in events[0].text
