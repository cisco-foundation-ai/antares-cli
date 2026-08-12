# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the scripted mock inference backend."""

from __future__ import annotations

import json
from collections.abc import Iterator

from antares_cli.agent.contracts import (
    RANKED_FILES_ARGUMENT,
    SUBMIT_VULNERABLE_FILES_TOOL,
    TERMINAL_TOOL_NAME,
)
from antares_cli.agent.streaming import (
    ParsedDoneSignal,
    ParsedToolCall,
    StreamingToolCallParser,
)
from antares_cli.inference.backend import InferenceBackend

_SUBMIT_SAMPLE_REPO_FILES = {
    "name": SUBMIT_VULNERABLE_FILES_TOOL,
    "arguments": {RANKED_FILES_ARGUMENT: ["app.py", "settings.py"]},
}

DEFAULT_AUDIT_SCRIPT = (
    "I'll start by examining the project structure to understand what files are present.\n\n"
    f'<tool_call>\n{{"tool": "{TERMINAL_TOOL_NAME}", "args": {{"command": "tree -L 2"}}}}\n</tool_call>\n\n'
    "The project contains app.py and settings.py. Let me review each file for vulnerabilities.\n\n"
    f'<tool_call>\n{{"tool": "{TERMINAL_TOOL_NAME}", "args": {{"command": "cat app.py"}}}}\n</tool_call>\n\n'
    "I see several serious issues in app.py. Let me also check the settings file.\n\n"
    f'<tool_call>\n{{"tool": "{TERMINAL_TOOL_NAME}", "args": {{"command": "cat settings.py"}}}}\n</tool_call>\n\n'
    "Now I have a complete file-level submission.\n\n"
    f"<tool_call>\n{json.dumps(_SUBMIT_SAMPLE_REPO_FILES)}\n</tool_call>\n"
)


class ScriptedInferenceBackend(InferenceBackend):
    def __init__(self, *, script: str | None = None) -> None:
        super().__init__(model_id="antares-1b")
        self._script = script if script is not None else DEFAULT_AUDIT_SCRIPT

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        yield from self._script


def test_default_script_produces_valid_events() -> None:
    backend = ScriptedInferenceBackend()
    parser = StreamingToolCallParser()

    messages = [{"role": "user", "content": "audit"}]
    full_output = "".join(backend.stream_generate(messages))
    events = parser.feed(full_output)
    events.extend(parser.flush())

    tool_calls = [e for e in events if isinstance(e, ParsedToolCall)]
    done_signals = [e for e in events if isinstance(e, ParsedDoneSignal)]

    assert len(tool_calls) == 4
    assert tool_calls[0].tool_name == "terminal"
    assert tool_calls[1].tool_name == "terminal"
    assert tool_calls[2].tool_name == "terminal"
    assert tool_calls[3].tool_name == "submit_vulnerable_files"
    assert tool_calls[3].arguments == {"ranked_files": ["app.py", "settings.py"]}

    assert done_signals == []


def test_custom_script_works() -> None:
    custom_script = '<done>\n{"total_findings": 0, "tool_call_count": 0}\n</done>'
    backend = ScriptedInferenceBackend(script=custom_script)

    full_output = "".join(backend.stream_generate([{"role": "user", "content": "audit"}]))
    parser = StreamingToolCallParser()
    events = parser.feed(full_output)
    events.extend(parser.flush())

    done_signals = [e for e in events if isinstance(e, ParsedDoneSignal)]
    assert len(done_signals) == 1


def test_character_by_character_streaming() -> None:
    backend = ScriptedInferenceBackend()
    characters = list(backend.stream_generate([{"role": "user", "content": "audit"}]))

    for character in characters:
        assert len(character) == 1

    reassembled = "".join(characters)
    assert reassembled == "".join(backend.stream_generate([{"role": "user", "content": "audit"}]))
