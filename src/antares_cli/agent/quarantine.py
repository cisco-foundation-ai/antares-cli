# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prompt-injection quarantine for untrusted repo and document content."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from antares_cli.agent.contracts import BASH_TOOL_NAME, TERMINAL_TOOL_NAME
from antares_cli.tools.shell_exec import (
    _parse_read_only_command_stages,
    _path_candidates,
    _references_sensitive_path,
)


@dataclass(frozen=True)
class QuarantinedSpan:
    start_offset: int
    end_offset: int
    pattern_name: str
    risk_level: Literal["high", "medium", "low"]


@dataclass(frozen=True)
class QuarantineResult:
    original_text: str
    sanitized_text: str
    quarantined_spans: tuple[QuarantinedSpan, ...]

    @property
    def injection_detected(self) -> bool:
        return len(self.quarantined_spans) > 0


_RISK_PRIORITY: dict[str, int] = {"high": 3, "medium": 2, "low": 1}

_BUILTIN_PATTERNS: list[tuple[str, str, Literal["high", "medium", "low"]]] = [
    (
        r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior|earlier)"
        r"\s+(?:instructions|prompts|rules|context)",
        "instruction_override",
        "high",
    ),
    (
        r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you(?:'re|\s+are))"
        r"|from\s+now\s+on\s+you)",
        "role_hijack",
        "high",
    ),
    (
        r"(?i)(?:reveal|show|print|output|display|repeat)\s+(?:your|the)"
        r"\s+(?:system\s+)?(?:prompt|instructions|rules)",
        "system_prompt_leak",
        "high",
    ),
    (
        r"(?i)<tool_call>.*?</tool_call>",
        "injected_tool_call_tag",
        "high",
    ),
    (
        r"(?i)<finding>.*?</finding>",
        "injected_finding_tag",
        "high",
    ),
    (
        r"(?i)<done>.*?</done>",
        "injected_done_tag",
        "high",
    ),
    (
        r"(?i)(?:###|---|===|\*\*\*)\s*(?:system|instruction|admin|root|override)",
        "delimiter_injection",
        "medium",
    ),
    (
        r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){4,}",
        "encoded_escape_sequence",
        "medium",
    ),
    (
        r"(?i)(?:IMPORTANT|CRITICAL|URGENT|WARNING):\s*(?:ignore|override|bypass|skip|disable)",
        "suspicious_directive",
        "low",
    ),
    (
        r"(?i)(?:<!--\s*|/\*\s*)\s*(?:ignore|override|system|admin|instruction)",
        "hidden_comment_directive",
        "low",
    ),
]


@dataclass
class ContentQuarantine:
    _compiled_patterns: list[tuple[re.Pattern[str], str, Literal["high", "medium", "low"]]] = field(
        init=False, repr=False
    )

    def __init__(
        self,
        additional_patterns: list[tuple[str, str, Literal["high", "medium", "low"]]] | None = None,
    ) -> None:
        all_raw_patterns = list(_BUILTIN_PATTERNS)
        if additional_patterns is not None:
            all_raw_patterns.extend(additional_patterns)

        self._compiled_patterns = []
        for regex_string, pattern_name, risk_level in all_raw_patterns:
            compiled = re.compile(regex_string, re.DOTALL)
            self._compiled_patterns.append((compiled, pattern_name, risk_level))

    def scan(self, text: str) -> QuarantineResult:
        all_matches: list[tuple[re.Match[str], str, Literal["high", "medium", "low"]]] = []
        for compiled_regex, pattern_name, risk_level in self._compiled_patterns:
            for match in compiled_regex.finditer(text):
                all_matches.append((match, pattern_name, risk_level))

        resolved_spans = _resolve_overlaps(all_matches)
        resolved_spans.sort(key=lambda span: span.start_offset)

        sanitized_text = _build_sanitized_text(text, resolved_spans)

        return QuarantineResult(
            original_text=text,
            sanitized_text=sanitized_text,
            quarantined_spans=tuple(resolved_spans),
        )


def _resolve_overlaps(
    all_matches: list[tuple[re.Match[str], str, Literal["high", "medium", "low"]]],
) -> list[QuarantinedSpan]:
    if not all_matches:
        return []

    candidate_spans: list[QuarantinedSpan] = []
    for match, pattern_name, risk_level in all_matches:
        candidate_spans.append(
            QuarantinedSpan(
                start_offset=match.start(),
                end_offset=match.end(),
                pattern_name=pattern_name,
                risk_level=risk_level,
            )
        )

    candidate_spans.sort(key=lambda span: (-_RISK_PRIORITY[span.risk_level], span.start_offset))

    kept_spans: list[QuarantinedSpan] = []
    for candidate in candidate_spans:
        overlaps_with_kept = False
        for kept in kept_spans:
            if (
                candidate.start_offset < kept.end_offset
                and candidate.end_offset > kept.start_offset
            ):
                overlaps_with_kept = True
                break
        if not overlaps_with_kept:
            kept_spans.append(candidate)

    return kept_spans


def _build_sanitized_text(
    original_text: str,
    sorted_spans: list[QuarantinedSpan],
) -> str:
    if not sorted_spans:
        return original_text

    parts: list[str] = []
    current_position = 0
    for span in sorted_spans:
        parts.append(original_text[current_position : span.start_offset])
        parts.append(f"[QUARANTINED: {span.pattern_name}]")
        current_position = span.end_offset
    parts.append(original_text[current_position:])
    return "".join(parts)


@dataclass(frozen=True)
class ToolCallSafetyCheck:
    safe: bool
    warnings: tuple[str, ...]
    blocked_reason: str | None = None


def validate_tool_call_safety(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    allowed_sensitive_files: tuple[str, ...] = (),
) -> ToolCallSafetyCheck:
    quarantine = ContentQuarantine()
    warnings: list[str] = []
    blocked_reason: str | None = None

    if tool_name in {BASH_TOOL_NAME, TERMINAL_TOOL_NAME} and "command" in arguments:
        command = str(arguments["command"])
        command_scan_result = quarantine.scan(command)
        high_risk_spans = [
            span for span in command_scan_result.quarantined_spans if span.risk_level == "high"
        ]
        if high_risk_spans:
            pattern_names = ", ".join(span.pattern_name for span in high_risk_spans)
            blocked_reason = f"Command blocked due to high-risk injection patterns: {pattern_names}"
        try:
            stages = _parse_read_only_command_stages(command)
        except ValueError:
            stages = []
        for stage in stages:
            for token in stage[1:]:
                for path_candidate in _path_candidates(token):
                    if _references_sensitive_path(path_candidate, allowed_sensitive_files):
                        blocked_reason = blocked_reason or (
                            f"Sensitive path blocked in argument 'command': {path_candidate}"
                        )

    for argument_key, argument_value in arguments.items():
        if not isinstance(argument_value, str):
            continue

        if tool_name not in {BASH_TOOL_NAME, TERMINAL_TOOL_NAME} and _references_sensitive_path(
            argument_value, allowed_sensitive_files
        ):
            blocked_reason = blocked_reason or (
                f"Sensitive path blocked in argument '{argument_key}': {argument_value}"
            )

        argument_scan_result = quarantine.scan(argument_value)
        high_risk_argument_spans = [
            span for span in argument_scan_result.quarantined_spans if span.risk_level == "high"
        ]
        if high_risk_argument_spans:
            pattern_names = ", ".join(span.pattern_name for span in high_risk_argument_spans)
            warnings.append(
                f"Argument '{argument_key}' contains high-risk injection patterns: {pattern_names}"
            )

    is_safe = blocked_reason is None
    return ToolCallSafetyCheck(
        safe=is_safe,
        warnings=tuple(warnings),
        blocked_reason=blocked_reason,
    )
