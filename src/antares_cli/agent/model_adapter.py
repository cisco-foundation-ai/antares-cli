# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Model adapters — one class, one registry.

Each adapter is a frozen configuration object that fully describes how a model
variant behaves: what system prompt it uses, how to format tool responses, how
to clean output text, and how to build the CWE user message. The agent loop is
model-agnostic — it delegates all formatting decisions to the adapter.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from antares_cli.agent.contracts import (
    SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
    SUBMIT_VULNERABLE_FILES_TOOL,
    TERMINAL_TOOL_NAME,
)
from antares_cli.agent.execution_policy import resolve_terminal_call_budget
from antares_cli.agent.streaming import (
    _EOS_TOKENS,
    _THINK_TAGS,
    ParsedEvent,
    ParsedToolCall,
    StreamingToolCallParser,
)

_TOOL_CALL_BLOCK = re.compile(r"<tool_call>.*?</tool_call>", re.DOTALL)


class ModelOutputParser(Protocol):
    def feed(self, text_chunk: str) -> list[ParsedEvent]: ...

    def flush(self) -> list[ParsedEvent]: ...


@dataclass(slots=True, frozen=True)
class ToolCallResult:
    """One executed tool call within a model turn."""

    tool_name: str
    tool_response: str


@dataclass(slots=True, frozen=True)
class ModelAdapter:
    """Single authoritative model configuration.

    All model-specific behavior lives here: prompts, output cleaning,
    message formatting, tool response wrapping. The agent loop never
    branches on model identity — it asks the adapter.
    """

    name: str
    investigation_system_prompt: str
    preserve_think_in_answer: bool = False
    strip_tool_calls_from_text: bool = True
    investigation_nudge_fraction: float = 0.75
    parser_factory: Callable[[], ModelOutputParser] = StreamingToolCallParser
    tool_response_role: str = "user"
    no_tool_retry_limit: int = 1

    def build_system_prompt(
        self,
        *,
        terminal_call_budget: int | None = None,
    ) -> str:
        resolved_budget = resolve_terminal_call_budget(terminal_call_budget)
        base_prompt = self.investigation_system_prompt.replace(
            "{terminal_call_budget}",
            str(resolved_budget),
        )
        return base_prompt

    def create_output_parser(self) -> ModelOutputParser:
        return self.parser_factory()

    def clean_model_text(self, text: str) -> str:
        cleaned = _EOS_TOKENS.sub("", text)
        if not self.preserve_think_in_answer:
            cleaned = _THINK_TAGS.sub("", cleaned)
        if self.strip_tool_calls_from_text:
            cleaned = _TOOL_CALL_BLOCK.sub("", cleaned)
        return cleaned.strip()

    def format_initial_messages(
        self,
        *,
        system_prompt: str,
        user_content: str,
    ) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

    def format_no_tool_retry(self, *, iteration_index: int = 0) -> dict[str, str]:
        is_final = iteration_index >= self.no_tool_retry_limit - 1
        if iteration_index == 0:
            content = (
                "You must use tools to investigate before reporting. "
                f"Start by calling {TERMINAL_TOOL_NAME} to examine the code. "
                f"When finished, submit file paths with {SUBMIT_VULNERABLE_FILES_TOOL} "
                f"or call {SUBMIT_NO_VULNERABILITY_FOUND_TOOL}."
            )
        elif is_final:
            content = (
                f"Call {SUBMIT_VULNERABLE_FILES_TOOL} with the file paths you identified, "
                f"or call {SUBMIT_NO_VULNERABILITY_FOUND_TOOL} if you found nothing."
            )
        else:
            content = f"Continue investigating. Use {TERMINAL_TOOL_NAME} to read more source files."
        return {"role": self.tool_response_role, "content": content}

    def format_duplicate_tool_retry(self, *, force_submit: bool) -> dict[str, str]:
        if force_submit:
            content = (
                "You have repeated the same tool calls 3 times. "
                "Stop investigating. Summarize what you found and "
                f"submit file-level results now using {SUBMIT_VULNERABLE_FILES_TOOL}. "
                f"If you found nothing, call {SUBMIT_NO_VULNERABILITY_FOUND_TOOL}."
            )
        else:
            content = (
                "You already called these tools with these exact arguments. "
                "Please try a different approach."
            )
        return {"role": self.tool_response_role, "content": content}

    def format_tool_results(
        self,
        results: Sequence[ToolCallResult],
        *,
        nudge_suffix: str = "",
    ) -> dict[str, str]:
        if self.tool_response_role == "tool_response":
            content = (
                results[0].tool_response
                if len(results) == 1
                else "\n\n".join(r.tool_response for r in results)
            )
            if nudge_suffix:
                content += nudge_suffix
        elif len(results) == 1:
            content = f"<tool_response>\n{results[0].tool_response}{nudge_suffix}\n</tool_response>"
        else:
            response_sections = [
                f'<tool_response id="{index}">\n{result.tool_response}\n</tool_response>'
                for index, result in enumerate(results, start=1)
            ]
            content = "\n\n".join(response_sections)
            if nudge_suffix:
                content += nudge_suffix
        return {"role": self.tool_response_role, "content": content}

    def extract_submit_tool_calls(
        self,
        text: str,
        *,
        is_submit_tool_call: Callable[[ParsedToolCall], bool],
    ) -> list[ParsedToolCall]:
        parser = self.create_output_parser()
        events = parser.feed(text)
        events.extend(parser.flush())
        return [
            event
            for event in events
            if isinstance(event, ParsedToolCall) and is_submit_tool_call(event)
        ]


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_ANTARES_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "terminal",
            "description": "Execute a read-only terminal command in the repository. Allowed: ls, tree, find, cat, head, tail, sed, grep, rg, wc, sort, uniq, cut, file, stat, du, pwd, nl, basename, dirname, realpath, diff, echo, true, false. Pipes and read-only &&, ||, and ; chains are OK. No interpreters, writes, redirects, or network commands.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to run"},
                    "max_chars": {
                        "type": "integer",
                        "description": "Max output chars (default 2000)",
                        "default": 2000,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read one repository-relative file with optional inclusive line bounds. "
                "Use this instead of terminal when you already know the exact path."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Repository-relative file path"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_vulnerable_files",
            "description": "Submit your answer: a ranked list of file paths you believe contain the vulnerability. Most likely vulnerable file first. Paths relative to repository root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ranked_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Ordered list of file paths, most vulnerable first",
                    }
                },
                "required": ["ranked_files"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_no_vulnerability_found",
            "description": "Declare that no vulnerability matching the CWE description was found in this codebase.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


def _build_antares_investigation_prompt() -> str:
    tools_block = (
        "<tools>\n" + "\n".join(json.dumps(t) for t in _ANTARES_TOOLS_SCHEMA) + "\n</tools>"
    )
    return (
        "You are a security vulnerability localization agent. You have read-only terminal access to a codebase.\n\n"
        "Given a CWE (Common Weakness Enumeration) description, your task is to determine whether this codebase "
        "contains a vulnerability matching that CWE class, and if so, identify which source file(s) are vulnerable.\n\n"
        "You can explore the codebase using the `terminal` tool — it runs read-only commands "
        "(ls, find, cat, head, tail, grep, rg, tree, etc.) inside the repository. "
        "You have up to {terminal_call_budget} repository tool calls.\n\n"
        "When you're done exploring:\n"
        "- If you found vulnerable file(s): call `submit_vulnerable_files` with a ranked list of file paths "
        "(most likely vulnerable first).\n"
        "- If you believe this codebase does NOT contain the described vulnerability: call "
        "`submit_no_vulnerability_found`.\n\n"
        "You may be looking at code that has already been patched — in that case, the correct answer is to submit "
        "nothing. Do not guess or hallucinate files. Only submit files you have evidence for.\n\n"
        "NOTE: Submitted paths must be exact file paths (e.g. src/utils.js), never globs or wildcards.\n\n"
        "You are a helpful assistant with access to the following tools. "
        "You may call one or more tools to assist with the user query.\n\n"
        "You are provided with function signatures within <tools></tools> XML tags:\n"
        f"{tools_block}\n\n"
        "For each tool call, return a json object with function name and arguments "
        "within <tool_call></tool_call> XML tags:\n"
        "<tool_call>\n"
        '{"name": <function-name>, "arguments": <args-json-object>}\n'
        "</tool_call>. If a tool does not exist in the provided list of tools, "
        "notify the user that you do not have the ability to fulfill the request."
    )


# ---------------------------------------------------------------------------
# Adapter instances
# ---------------------------------------------------------------------------

ANTARES_ADAPTER = ModelAdapter(
    name="antares",
    investigation_system_prompt=_build_antares_investigation_prompt(),
    tool_response_role="tool_response",
    no_tool_retry_limit=5,
)

MODEL_ADAPTER_REGISTRY: dict[str, ModelAdapter] = {
    "antares": ANTARES_ADAPTER,
}

DEFAULT_ADAPTER = ANTARES_ADAPTER


def resolve_model_adapter(identifier: str) -> ModelAdapter:
    normalized = identifier.lower().strip()
    if normalized in MODEL_ADAPTER_REGISTRY:
        return MODEL_ADAPTER_REGISTRY[normalized]
    return DEFAULT_ADAPTER
