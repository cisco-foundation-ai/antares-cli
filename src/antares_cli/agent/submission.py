# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Final submission handling for model-driven audits."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from antares_cli.agent.contracts import (
    RANKED_FILE_ARGUMENT_ALIASES,
    RANKED_FILES_ARGUMENT,
    SUBMIT_FILE_PATH_FIELD_ALIASES,
    SUBMIT_NO_VULNERABILITY_FOUND_TOOL,
    SUBMIT_VULNERABLE_FILES_TOOL,
    BuildAgentStateFn,
    ProgressCallback,
)
from antares_cli.agent.state import ModelSessionState
from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.output.finding import Finding, TrajectoryEntry

INVALID_FINDING_PATHS = {"unknown", "", "n/a", "none"}
INVALID_SUBMISSION_MESSAGE = "Model submitted no valid repository file paths."


class SubmissionHandler:
    """Converts final submit tool calls into canonical file-level findings."""

    def __init__(
        self,
        *,
        cwe_database: CweDatabase,
        build_agent_state: BuildAgentStateFn,
        submission_root: Path,
    ) -> None:
        self.cwe_database = cwe_database
        self.build_agent_state = build_agent_state
        self.submission_root = submission_root.resolve()

    def handle(
        self,
        parsed_call: ParsedToolCall,
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> list[Finding]:
        submit_tool_name = parsed_call.tool_name.strip().lower()
        self._record_submission_call(parsed_call, state)
        if submit_tool_name == SUBMIT_NO_VULNERABILITY_FOUND_TOOL:
            state.result_submitted = True
            state.submission_error = None
            self._record_no_vulnerability_submission(submit_tool_name, state)
            return []
        new_findings = self._record_vulnerable_file_submission(
            submit_tool_name,
            parsed_call.arguments,
            state,
            progress_callback=progress_callback,
        )
        if new_findings:
            state.result_submitted = True
            state.submission_error = None
        else:
            state.result_submitted = False
            state.submission_error = INVALID_SUBMISSION_MESSAGE
            state.reasoning_log.append(f"Submit tool: {INVALID_SUBMISSION_MESSAGE}")
        return new_findings

    def extract_ranked_file_paths(
        self,
        arguments: dict[str, Any],
    ) -> list[str]:
        raw_files = _first_present_argument(arguments, RANKED_FILE_ARGUMENT_ALIASES)
        if not isinstance(raw_files, list):
            return []
        ranked_files: list[str] = []
        seen: set[str] = set()
        for raw_entry in raw_files:
            normalized = _normalize_ranked_file_entry(raw_entry, self.submission_root)
            if normalized and normalized not in seen:
                ranked_files.append(normalized)
                seen.add(normalized)
        return ranked_files

    @staticmethod
    def _record_submission_call(parsed_call: ParsedToolCall, state: ModelSessionState) -> None:
        state.done_signaled = True
        state.tool_call_count += 1
        state.session_trace.record_tool_call(
            tool_name=parsed_call.tool_name,
            arguments=parsed_call.arguments,
        )

    @staticmethod
    def _record_no_vulnerability_submission(
        submit_tool_name: str,
        state: ModelSessionState,
    ) -> None:
        state.reasoning_log.append("Submit tool: model reported no vulnerable files.")
        state.session_trace.record_event(
            phase="final_submission",
            payload={"tool_name": submit_tool_name, RANKED_FILES_ARGUMENT: []},
        )
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="tool_call",
                content=f"-> {SUBMIT_NO_VULNERABILITY_FOUND_TOOL}()",
            )
        )

    def _record_vulnerable_file_submission(
        self,
        submit_tool_name: str,
        arguments: dict[str, Any],
        state: ModelSessionState,
        *,
        progress_callback: ProgressCallback | None,
    ) -> list[Finding]:
        ranked_files = self.extract_ranked_file_paths(arguments)
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="tool_call",
                content=f"-> {SUBMIT_VULNERABLE_FILES_TOOL}({RANKED_FILES_ARGUMENT}={ranked_files})",
            )
        )
        new_findings = self._collect_findings(ranked_files, state, progress_callback)
        state.session_trace.record_event(
            phase="final_submission",
            payload={"tool_name": submit_tool_name, RANKED_FILES_ARGUMENT: ranked_files},
        )
        state.reasoning_log.append(
            f"Submit tool: collected {len(new_findings)} file-level vulnerable file(s)."
        )
        return new_findings

    def _collect_findings(
        self,
        ranked_files: list[str],
        state: ModelSessionState,
        progress_callback: ProgressCallback | None,
    ) -> list[Finding]:
        new_findings: list[Finding] = []
        for rank, file_path in enumerate(ranked_files, start=1):
            finding = self._build_file_level_finding(file_path, state, rank=rank)
            if not finding_is_valid(finding, self.submission_root):
                state.reasoning_log.append(f"Submit tool: ignored invalid file path '{file_path}'")
                continue
            if self._record_finding(finding, state):
                new_findings.append(finding)
                self._publish_progress(state, finding, progress_callback)
        return new_findings

    def _build_file_level_finding(
        self,
        file_path: str,
        state: ModelSessionState,
        *,
        rank: int,
    ) -> Finding:
        cwe_ids = _normalize_focus_cwe_ids(state.focus_cwe_ids)
        confidence = max(0.5, 0.95 - ((rank - 1) * 0.05))
        likelihood_of_exploit = self._highest_likelihood_for_cwes(cwe_ids)
        return Finding(
            title=self._file_level_title_for_cwes(cwe_ids),
            file_path=file_path,
            cwe_ids=cwe_ids,
            confidence=confidence,
            submission_rank=rank,
            likelihood_of_exploit=likelihood_of_exploit,
        )

    def _highest_likelihood_for_cwes(self, cwe_ids: list[str]) -> str:
        likelihood_rank = {"High": 3, "Medium": 2, "Low": 1}
        highest = ""
        highest_rank = 0
        for cwe_id in cwe_ids:
            entry = self.cwe_database.get_by_id(cwe_id)
            if entry is None:
                continue
            rank = likelihood_rank.get(entry.likelihood_of_exploit, 0)
            if rank > highest_rank:
                highest_rank = rank
                highest = entry.likelihood_of_exploit
        return highest

    def _file_level_title_for_cwes(self, cwe_ids: list[str]) -> str:
        titles = [
            entry.name if (entry := self.cwe_database.get_by_id(cwe_id)) is not None else cwe_id
            for cwe_id in cwe_ids
        ]
        return " / ".join(titles) if titles else "Submitted vulnerable file"

    @staticmethod
    def _record_finding(
        finding: Finding,
        state: ModelSessionState,
    ) -> bool:
        dedupe_key = (finding.file_path, finding.title)
        if dedupe_key in state.dedupe_keys:
            return False
        state.dedupe_keys.add(dedupe_key)
        state.findings.append(finding)
        finding_dict = finding.to_dict()
        state.session_trace.record_finding(
            finding_dict=finding_dict,
            evidence_id=state.session_trace.new_evidence_id(),
        )
        state.trajectory.append(
            TrajectoryEntry(
                entry_type="finding",
                content=f"file-level: {finding.file_path}",
            )
        )
        return True

    def _publish_progress(
        self,
        state: ModelSessionState,
        finding: Finding,
        progress_callback: ProgressCallback | None,
    ) -> None:
        if progress_callback is None:
            return
        progress_callback(
            self.build_agent_state(
                messages=state.messages,
                trajectory=state.trajectory,
            ),
            finding,
        )


def _first_present_argument(
    arguments: dict[str, Any],
    aliases: tuple[str, ...],
) -> object:
    for alias in aliases:
        if alias in arguments:
            return arguments[alias]
    return None


def _normalize_ranked_file_entry(raw_entry: object, repository_path: Path) -> str:
    if isinstance(raw_entry, str):
        return _normalize_submitted_file_path(raw_entry, repository_path)
    if not isinstance(raw_entry, dict):
        return ""
    file_path = _first_present_argument(raw_entry, SUBMIT_FILE_PATH_FIELD_ALIASES)
    if not isinstance(file_path, str):
        return ""
    return _normalize_submitted_file_path(file_path, repository_path)


def _normalize_submitted_file_path(raw_path: str, repository_path: Path) -> str:
    path_text = raw_path.strip().replace("\\", "/")
    if not path_text:
        return ""
    while path_text.startswith("./"):
        path_text = path_text[2:]
    if not path_text:
        return ""
    repository_root = repository_path.resolve()
    candidate = _resolve_exact_repository_path(path_text, repository_root)
    if candidate is None:
        return ""
    return candidate.relative_to(repository_root).as_posix()


def _normalize_focus_cwe_ids(focus_cwe_ids: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_cwe in focus_cwe_ids:
        cwe_id = _normalize_cwe_id(raw_cwe)
        if cwe_id and cwe_id not in seen:
            normalized.append(cwe_id)
            seen.add(cwe_id)
    return normalized


def _normalize_cwe_id(raw_cwe: str) -> str:
    from antares_cli.core.cwe import normalize_cwe_id

    return normalize_cwe_id(raw_cwe, strict=False)


def finding_is_valid(finding: Finding, repository_path: Path | None = None) -> bool:
    if not _finding_metadata_is_valid(finding):
        return False
    if repository_path is None:
        return True
    candidate = _resolve_exact_repository_path(finding.file_path, repository_path.resolve())
    if candidate is None:
        return False
    try:
        return candidate.is_file()
    except OSError:
        return False


def _finding_metadata_is_valid(finding: Finding) -> bool:
    if finding.file_path.lower().strip() in INVALID_FINDING_PATHS:
        return False
    return bool(finding.title) and len(finding.title) >= 5


def _resolve_exact_repository_path(file_path: str, repository_root: Path) -> Path | None:
    """Resolve a confined path only when every submitted component has exact casing."""
    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = repository_root / candidate
    try:
        resolved = candidate.resolve()
        relative = resolved.relative_to(repository_root)
    except (OSError, ValueError):
        return None
    if not _relative_path_has_exact_spelling(repository_root, relative):
        return None
    return resolved


def _relative_path_has_exact_spelling(repository_root: Path, relative: Path) -> bool:
    """Check path spelling independently of host filesystem case sensitivity."""
    directory = repository_root
    for component in relative.parts:
        try:
            with os.scandir(directory) as entries:
                if not any(entry.name == component for entry in entries):
                    return False
        except OSError:
            return False
        directory /= component
    return True
