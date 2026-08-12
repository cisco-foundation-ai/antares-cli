# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Granite prompt serialization and tokenizer-independent capacity bounds."""

from __future__ import annotations

import re

_CONTEXT_SAFETY_TOKENS = 512
_GRANITE_CONTROL_TOKENS = (
    "<|start_of_role|>",
    "<|end_of_role|>",
    "<|end_of_text|>",
    "<|endoftext|>",
    "<|eot_id|>",
)
_TOOL_RESPONSE_DELIMITER = re.compile(r"</?tool_response(?:\s+[^>]*)?>", re.IGNORECASE)
_ASSISTANT_PREFILL = "<|start_of_role|>assistant<|end_of_role|><think>\n"


def apply_granite_chat_template(messages: list[dict[str, str]]) -> str:
    """Serialize model messages exactly as the completions endpoint receives them."""
    parts = [_serialize_granite_message(message) for message in messages]
    parts.append(_ASSISTANT_PREFILL)
    return "\n".join(parts)


def granite_message_token_upper_bound(message: dict[str, str]) -> int:
    """Bound one serialized message, including its following prompt newline."""
    return _encoded_size(_serialize_granite_message(message)) + 1


def granite_prompt_token_upper_bound(messages: list[dict[str, str]]) -> int:
    """Bound Granite tokens by the fully escaped prompt's UTF-8 byte count.

    Granite's byte-level tokenizer can merge byte sequences into one token but
    cannot emit more tokens than the serialized prompt contains bytes. Counting
    the final prompt bytes is therefore conservative without a tokenizer or a
    network request at runtime.
    """
    return _encoded_size(apply_granite_chat_template(messages))


def _serialize_granite_message(message: dict[str, str]) -> str:
    role = message["role"]
    content = _escape_granite_control_tokens(message["content"])
    if role == "assistant":
        prefixed = content if content.startswith("<think>") else f"<think>\n{content}"
        return f"<|start_of_role|>assistant<|end_of_role|>{prefixed}<|end_of_text|>"
    if role == "tool_response":
        content = _TOOL_RESPONSE_DELIMITER.sub(
            "[escaped tool-response delimiter]",
            content,
        )
        return (
            "<|start_of_role|>user<|end_of_role|>\n<tool_response>\n"
            f"{content}\n</tool_response><|end_of_text|>"
        )
    return f"<|start_of_role|>{role}<|end_of_role|>{content}<|end_of_text|>"


def _escape_granite_control_tokens(content: str) -> str:
    """Keep untrusted message text from creating forged raw-template turns."""
    for token in _GRANITE_CONTROL_TOKENS:
        token_name = token.removeprefix("<|").removesuffix("|>")
        content = content.replace(token, f"[escaped Granite control token: {token_name}]")
    return content


def _encoded_size(text: str) -> int:
    return len(text.encode("utf-8", errors="backslashreplace"))


FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND = _encoded_size(_ASSISTANT_PREFILL)
MINIMUM_SERIALIZED_MESSAGE_TOKENS = max(
    granite_message_token_upper_bound({"role": role, "content": ""})
    for role in ("system", "user", "assistant", "tool_response")
)
MINIMUM_SERIALIZED_PROMPT_TOKENS = (
    2 * MINIMUM_SERIALIZED_MESSAGE_TOKENS + FINAL_ASSISTANT_PREFILL_TOKEN_UPPER_BOUND
)


def prompt_token_budget(*, context_window: int, reserved_output_tokens: int) -> int:
    """Reserve output, template variance, and a usable serialized prompt."""
    if isinstance(context_window, bool) or not isinstance(context_window, int):
        raise ValueError("Model context_window must be an integer")
    if isinstance(reserved_output_tokens, bool) or not isinstance(reserved_output_tokens, int):
        raise ValueError("Reserved output tokens must be an integer")
    if context_window < 1 or reserved_output_tokens < 1:
        raise ValueError("Context window and reserved output tokens must be positive")
    if reserved_output_tokens >= context_window:
        raise ValueError("Reserved output tokens must be smaller than the context window")

    safety_tokens = max(_CONTEXT_SAFETY_TOKENS, context_window // 20)
    available = context_window - reserved_output_tokens - safety_tokens
    if available < MINIMUM_SERIALIZED_PROMPT_TOKENS:
        required_headroom = safety_tokens + MINIMUM_SERIALIZED_PROMPT_TOKENS
        raise ValueError(
            "Context window and max_tokens must leave at least "
            f"{required_headroom} tokens for the serialized prompt and safety reserve"
        )
    return available
