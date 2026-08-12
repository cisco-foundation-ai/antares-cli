# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from antares_cli.agent.contracts import (
    RANKED_FILES_ARGUMENT,
    SUBMIT_VULNERABLE_FILES_TOOL,
    TERMINAL_TOOL_NAME,
    is_submit_tool_call,
)
from antares_cli.agent.model_adapter import (
    ANTARES_ADAPTER,
    ToolCallResult,
    resolve_model_adapter,
)
from antares_cli.agent.streaming import ParsedToolCall


def test_resolve_model_adapter_returns_antares_adapter() -> None:
    assert resolve_model_adapter("antares") is ANTARES_ADAPTER


def test_resolve_model_adapter_falls_back_to_antares_for_unknown() -> None:
    assert resolve_model_adapter("unknown-model") is ANTARES_ADAPTER


def test_adapter_formats_tool_results_as_tool_response_role() -> None:
    message = ANTARES_ADAPTER.format_tool_results(
        [
            ToolCallResult(
                tool_name=TERMINAL_TOOL_NAME,
                tool_response="file contents",
            )
        ]
    )

    assert message == {
        "role": "tool_response",
        "content": "file contents",
    }


def test_adapter_extracts_submit_tool_calls_from_supported_text_formats() -> None:
    calls = ANTARES_ADAPTER.extract_submit_tool_calls(
        f'{{"name":"{SUBMIT_VULNERABLE_FILES_TOOL}","arguments":{{"{RANKED_FILES_ARGUMENT}":["app.py"]}}}}',
        is_submit_tool_call=is_submit_tool_call,
    )

    assert calls == [
        ParsedToolCall(
            tool_name=SUBMIT_VULNERABLE_FILES_TOOL,
            arguments={RANKED_FILES_ARGUMENT: ["app.py"]},
        )
    ]
