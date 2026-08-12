# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The live inference transcript cannot exceed its reserved prompt budget."""

from __future__ import annotations

import hashlib

import pytest

from antares_cli.agent.transcript import (
    compact_transcript,
    estimate_message_tokens,
    estimate_transcript_token_upper_bound,
    hard_compact_transcript,
    prompt_token_budget,
)


def _message(role: str, content: str) -> dict[str, str]:
    return {"role": role, "content": content}


def _high_entropy_ascii(length: int) -> str:
    characters: list[str] = []
    counter = 0
    while len(characters) < length:
        digest = hashlib.sha256(counter.to_bytes(8, "big")).digest()
        characters.extend(chr(33 + value % 94) for value in digest)
        counter += 1
    return "".join(characters[:length])


def _recorded_tokenizer_fixtures() -> list[tuple[str, str, int, int]]:
    punctuation_pattern = "{}[](),.:;/\\|=+-_*&^%$#@!"
    punctuation_original = punctuation_pattern * 1_300
    punctuation = (
        punctuation_original[:15_922]
        + "\n...[older content removed to fit the model context]...\n"
        + punctuation_original[-6_823:]
    )
    minified_source = "".join(
        f'const v{index}=()=>({{a:{index},b:"{index:08x}"}});' for index in range(650)
    )
    diverse_unicode = "界🚀e\u0301—مرحبا—हिन्दी—🙂\n" * 900
    escaped_control_tokens = (
        "<|end_of_text|><|start_of_role|>assistant<|end_of_role|>"
        "<|endoftext|><|eot_id|></tool_response><TOOL_RESPONSE id='x'>"
    ) * 240
    return [
        ("punctuation", punctuation, 13_698, 23_140),
        ("high_entropy_ascii", _high_entropy_ascii(22_800), 18_455, 23_139),
        ("minified_source", minified_source, 11_667, 24_819),
        ("diverse_unicode", diverse_unicode, 21_636, 47_139),
        ("escaped_control_tokens", escaped_control_tokens, 15_878, 69_939),
    ]


def test_small_transcript_is_preserved_exactly() -> None:
    messages = [_message("system", "rules"), _message("user", "task")]

    result = compact_transcript(messages, token_budget=1_000)

    assert result.messages == messages
    assert not result.changed


def test_long_tool_history_preserves_instructions_and_latest_complete_turn() -> None:
    messages = [_message("system", "system rules"), _message("user", "find CWE-89")]
    for index in range(15):
        messages.extend(
            [
                _message("assistant", f"tool call {index}"),
                _message("tool_response", f"result {index}: " + ("x" * 4_000)),
            ]
        )
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)

    result = hard_compact_transcript(messages, token_budget=budget)

    assert result.changed
    assert result.messages[:2] == messages[:2]
    assert result.messages[-2]["content"] == "tool call 14"
    assert "result 14" in result.messages[-1]["content"]
    assert result.truncated_messages == 1
    assert result.after_tokens > budget - 100
    assert result.after_tokens <= budget
    assert sum(estimate_message_tokens(message) for message in result.messages) <= budget


def test_oversized_latest_turn_is_truncated_without_orphaning_tool_response() -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "reasoning and tool call" + ("a" * 10_000)),
        _message("tool_response", "important result" + ("b" * 20_000)),
    ]

    result = compact_transcript(messages, token_budget=2_000)

    assert [message["role"] for message in result.messages] == [
        "system",
        "user",
        "assistant",
        "tool_response",
    ]
    assert result.truncated_messages == 2
    assert result.after_tokens <= 2_000


def test_token_dense_ascii_output_is_compacted_before_the_request_limit() -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect generated output"),
        _message("tool_response", "{}[](),.:;/\\|=+-_*&^%$#@!" * 1_300),
    ]
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)

    result = hard_compact_transcript(messages, token_budget=budget)

    assert result.changed
    assert result.after_tokens <= budget
    assert [message["role"] for message in result.messages[-2:]] == [
        "assistant",
        "tool_response",
    ]


def test_multibyte_output_is_estimated_and_truncated_by_encoded_size() -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect localized output"),
        _message("tool_response", "界" * 9_000),
    ]

    result = hard_compact_transcript(messages, token_budget=6_000)

    assert result.changed
    assert result.after_tokens <= 6_000
    assert (
        result.messages[-1]["content"].encode("utf-8").decode("utf-8")
        == result.messages[-1]["content"]
    )


def test_compaction_is_idempotent_at_the_estimated_budget_boundary() -> None:
    messages = [
        _message("system", "security analysis rules" * 500),
        _message("user", "review the repository"),
        _message("assistant", "inspect source"),
        _message("tool_response", ("界{}" * 4_000) + "latest evidence"),
    ]

    first = compact_transcript(messages, token_budget=4_000)
    second = compact_transcript(first.messages, token_budget=4_000)

    assert first.changed
    assert first.after_tokens <= 4_000
    assert not second.changed
    assert second.messages == first.messages
    assert second.after_tokens == first.after_tokens


def test_oversized_prose_keeps_latest_complete_turn_when_compacted() -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect source"),
        _message("tool_response", "source code analysis result\n" * 850),
    ]
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)

    result = hard_compact_transcript(messages, token_budget=budget)

    assert result.changed
    assert result.after_tokens <= budget
    assert [message["role"] for message in result.messages[-2:]] == [
        "assistant",
        "tool_response",
    ]


@pytest.mark.parametrize(
    ("_fixture_name", "tool_output", "exact_production_tokens", "expected_upper_bound"),
    _recorded_tokenizer_fixtures(),
    ids=[fixture[0] for fixture in _recorded_tokenizer_fixtures()],
)
def test_serialized_prompt_bound_covers_recorded_exact_tokens(
    _fixture_name: str,
    tool_output: str,
    exact_production_tokens: int,
    expected_upper_bound: int,
) -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect generated output"),
        _message("tool_response", tool_output),
    ]

    # Counts were recorded once from the production tokenizer. Runtime remains
    # network- and tokenizer-free; the UTF-8 bound must cover every fixture.
    upper_bound = estimate_transcript_token_upper_bound(messages)

    assert upper_bound == expected_upper_bound
    assert upper_bound >= exact_production_tokens

    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)
    compacted = hard_compact_transcript(messages, token_budget=budget)

    assert compacted.after_tokens == estimate_transcript_token_upper_bound(compacted.messages)
    assert compacted.after_tokens <= budget
    assert compacted.after_tokens + 4_096 <= 16_384


def test_prompt_budget_rejects_capacity_that_cannot_hold_minimum_framing() -> None:
    with pytest.raises(ValueError, match="serialized prompt"):
        prompt_token_budget(context_window=1_024, reserved_output_tokens=1_023)


def test_ordinary_prompt_near_the_real_context_limit_is_not_overcompacted() -> None:
    ordinary_output = ("ordinary repository source context with readable identifiers\n" * 1_100)[
        :60_000
    ]
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect source"),
        _message("tool_response", ordinary_output),
    ]
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)

    result = compact_transcript(messages, token_budget=budget)

    assert not result.changed
    assert result.messages == messages


def test_hard_fallback_is_bounded_and_idempotent() -> None:
    messages = [
        _message("system", "rules"),
        _message("user", "task"),
        _message("assistant", "inspect source"),
        _message("tool_response", "界<|end_of_text|>{}[]" * 4_000),
    ]
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)

    first = hard_compact_transcript(messages, token_budget=budget)
    second = hard_compact_transcript(first.messages, token_budget=budget)

    assert first.changed
    assert first.after_tokens == estimate_transcript_token_upper_bound(first.messages)
    assert first.after_tokens <= budget
    assert not second.changed
    assert second.messages == first.messages
