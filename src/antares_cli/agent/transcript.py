# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bound the authoritative model transcript to the backend context window."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from antares_cli.inference.granite import (
    FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND,
    MINIMUM_SERIALIZED_MESSAGE_TOKENS,
    MINIMUM_SERIALIZED_PROMPT_TOKENS,
    granite_message_token_upper_bound,
    granite_prompt_token_upper_bound,
)
from antares_cli.inference.granite import (
    prompt_token_budget as _prompt_token_budget,
)

_NORMAL_MIN_MESSAGE_TOKENS = 32
_COMPACTION_MARKER = "\n...[older content removed to fit the model context]...\n"

MessageEstimator = Callable[[dict[str, str]], int]
TranscriptEstimator = Callable[[list[dict[str, str]]], int]


@dataclass(frozen=True, slots=True)
class TranscriptCompaction:
    messages: list[dict[str, str]]
    before_tokens: int
    after_tokens: int
    removed_messages: int
    truncated_messages: int

    @property
    def changed(self) -> bool:
        return self.removed_messages > 0 or self.truncated_messages > 0


def prompt_token_budget(*, context_window: int, reserved_output_tokens: int) -> int:
    """Return the validated prompt budget used by agent callers."""
    return _prompt_token_budget(
        context_window=context_window,
        reserved_output_tokens=reserved_output_tokens,
    )


def estimate_message_tokens(message: dict[str, str]) -> int:
    """Estimate ordinary Granite tokens from escaped, serialized bytes."""
    return _normal_token_estimate(granite_message_token_upper_bound(message))


def estimate_transcript_tokens(messages: list[dict[str, str]]) -> int:
    """Estimate ordinary Granite tokens from the serialized prompt."""
    return _normal_token_estimate(granite_prompt_token_upper_bound(messages))


def estimate_transcript_token_upper_bound(messages: list[dict[str, str]]) -> int:
    """Return the tokenizer-independent bound used after a size rejection."""
    return granite_prompt_token_upper_bound(messages)


def _normal_token_estimate(serialized_bytes: int) -> int:
    # Calibrated against ordinary source-heavy prompts; dense outliers are
    # recovered with the hard serialized-byte bound after a typed rejection.
    return math.ceil(serialized_bytes * 2 / 11)


def compact_transcript(
    messages: list[dict[str, str]],
    *,
    token_budget: int,
) -> TranscriptCompaction:
    """Compact with calibrated accounting for an ordinary model request."""
    return _compact_transcript(messages, token_budget=token_budget, hard_limit=False)


def hard_compact_transcript(
    messages: list[dict[str, str]],
    *,
    token_budget: int,
) -> TranscriptCompaction:
    """Compact with the serialized-byte bound after a context-size rejection."""
    return _compact_transcript(messages, token_budget=token_budget, hard_limit=True)


def _compact_transcript(
    messages: list[dict[str, str]],
    *,
    token_budget: int,
    hard_limit: bool,
) -> TranscriptCompaction:
    if token_budget < MINIMUM_SERIALIZED_PROMPT_TOKENS:
        raise ValueError("Transcript token budget is too small for the minimum serialized prompt")

    message_estimator: MessageEstimator = (
        granite_message_token_upper_bound if hard_limit else estimate_message_tokens
    )
    transcript_estimator: TranscriptEstimator = (
        granite_prompt_token_upper_bound if hard_limit else estimate_transcript_tokens
    )
    minimum_message_tokens = (
        MINIMUM_SERIALIZED_MESSAGE_TOKENS if hard_limit else _NORMAL_MIN_MESSAGE_TOKENS
    )
    final_prefill_tokens = (
        FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND
        if hard_limit
        else _normal_token_estimate(FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND)
    )
    before_tokens = transcript_estimator(messages)
    copied = [dict(message) for message in messages]
    if before_tokens <= token_budget:
        return TranscriptCompaction(copied, before_tokens, before_tokens, 0, 0)

    message_budget = token_budget - final_prefill_tokens
    initial_count = min(2, len(copied))
    initial_messages = copied[:initial_count]
    trailing_messages = copied[initial_count:]
    recent_reserve = (
        max(minimum_message_tokens * 2, message_budget // 3) if trailing_messages else 0
    )
    initial_budget = max(
        minimum_message_tokens * initial_count,
        message_budget - recent_reserve,
    )
    fitted_initial, initial_truncated = _fit_messages(
        initial_messages,
        initial_budget,
        estimator=message_estimator,
        minimum_message_tokens=minimum_message_tokens,
    )

    remaining = max(
        0,
        message_budget - sum(message_estimator(message) for message in fitted_initial),
    )
    turn_groups = [
        trailing_messages[index : index + 2] for index in range(0, len(trailing_messages), 2)
    ]
    retained_groups: list[list[dict[str, str]]] = []
    trailing_truncated = 0
    for group in reversed(turn_groups):
        group_tokens = sum(message_estimator(message) for message in group)
        if group_tokens <= remaining:
            retained_groups.append(group)
            remaining -= group_tokens
            continue
        if remaining >= minimum_message_tokens * len(group):
            fitted_group, group_truncated = _fit_messages(
                group,
                remaining,
                estimator=message_estimator,
                minimum_message_tokens=minimum_message_tokens,
            )
            retained_groups.append(fitted_group)
            trailing_truncated += group_truncated
        break

    retained_trailing = [message for group in reversed(retained_groups) for message in group]
    compacted = [*fitted_initial, *retained_trailing]
    after_tokens = transcript_estimator(compacted)
    return TranscriptCompaction(
        messages=compacted,
        before_tokens=before_tokens,
        after_tokens=after_tokens,
        removed_messages=len(messages) - len(compacted),
        truncated_messages=initial_truncated + trailing_truncated,
    )


def _fit_messages(
    messages: list[dict[str, str]],
    token_budget: int,
    *,
    estimator: MessageEstimator,
    minimum_message_tokens: int,
) -> tuple[list[dict[str, str]], int]:
    if not messages:
        return [], 0
    original_tokens = [estimator(message) for message in messages]
    if sum(original_tokens) <= token_budget:
        return messages, 0

    allocations = [minimum_message_tokens] * len(messages)
    remaining = max(0, token_budget - sum(allocations))
    unmet = [max(0, tokens - minimum_message_tokens) for tokens in original_tokens]
    while remaining > 0 and any(unmet):
        active_count = sum(value > 0 for value in unmet)
        share = max(1, remaining // active_count)
        for index, needed in enumerate(unmet):
            if needed <= 0 or remaining <= 0:
                continue
            granted = min(needed, share, remaining)
            allocations[index] += granted
            unmet[index] -= granted
            remaining -= granted

    fitted: list[dict[str, str]] = []
    truncated = 0
    for message, allocation in zip(messages, allocations, strict=True):
        fitted_message = _truncate_message(message, allocation, estimator=estimator)
        truncated += fitted_message != message
        fitted.append(fitted_message)
    return fitted, truncated


def _truncate_message(
    message: dict[str, str],
    token_budget: int,
    *,
    estimator: MessageEstimator,
) -> dict[str, str]:
    if estimator(message) <= token_budget:
        return message
    content = message.get("content", "")
    fitted_marker = _largest_fitting_prefix(
        message,
        _COMPACTION_MARKER,
        token_budget,
        estimator=estimator,
    )
    if fitted_marker != _COMPACTION_MARKER:
        return {**message, "content": fitted_marker}

    low = 0
    high = max(0, _encoded_size(content) - 1)
    compacted_content = _COMPACTION_MARKER
    while low <= high:
        retained_bytes = (low + high) // 2
        candidate = _content_edges(content, retained_bytes)
        candidate_message = {**message, "content": candidate}
        if estimator(candidate_message) <= token_budget:
            compacted_content = candidate
            low = retained_bytes + 1
        else:
            high = retained_bytes - 1
    return {**message, "content": compacted_content}


def _largest_fitting_prefix(
    message: dict[str, str],
    text: str,
    token_budget: int,
    *,
    estimator: MessageEstimator,
) -> str:
    low = 0
    high = _encoded_size(text)
    fitted = ""
    while low <= high:
        byte_budget = (low + high) // 2
        candidate = _utf8_prefix(text, byte_budget)
        if estimator({**message, "content": candidate}) <= token_budget:
            fitted = candidate
            low = byte_budget + 1
        else:
            high = byte_budget - 1
    return fitted


def _content_edges(content: str, retained_bytes: int) -> str:
    head_bytes = math.ceil(retained_bytes * 0.7)
    tail_bytes = retained_bytes - head_bytes
    return (
        _utf8_prefix(content, head_bytes) + _COMPACTION_MARKER + _utf8_suffix(content, tail_bytes)
    )


def _utf8_prefix(text: str, byte_budget: int) -> str:
    if byte_budget <= 0:
        return ""
    return text.encode("utf-8", errors="backslashreplace")[:byte_budget].decode(
        "utf-8", errors="ignore"
    )


def _utf8_suffix(text: str, byte_budget: int) -> str:
    if byte_budget <= 0:
        return ""
    return text.encode("utf-8", errors="backslashreplace")[-byte_budget:].decode(
        "utf-8", errors="ignore"
    )


def _encoded_size(text: str) -> int:
    return len(text.encode("utf-8", errors="backslashreplace"))
