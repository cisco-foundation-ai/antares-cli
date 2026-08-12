# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Finding and report summary dataclasses."""

from __future__ import annotations

import posixpath
from dataclasses import asdict, dataclass
from typing import Literal

from antares_cli.core.cwe import normalize_cwe_id as _strict_normalize_cwe_id


@dataclass(slots=True)
class Finding:
    title: str
    file_path: str
    cwe_ids: list[str]
    confidence: float
    submission_rank: int | None = None
    likelihood_of_exploit: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize the public finding contract."""
        payload = asdict(self)
        payload.pop("confidence", None)
        if self.submission_rank is None:
            payload.pop("submission_rank", None)
        return payload


@dataclass(slots=True)
class ReportSummary:
    total_findings: int
    tool_call_count: int
    duration_seconds: float
    cwe_ids_triggered: list[str]
    investigation_trace: str | None = None
    failed_tool_calls: int = 0
    retried_turns: int = 0
    generation_errors: int = 0
    failed_workers: int = 0
    total_workers: int = 0
    incomplete_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_public_dict(self) -> dict[str, object]:
        """Serialize report-safe fields while retaining private trace data in memory."""
        payload = self.to_dict()
        payload.pop("investigation_trace", None)
        return payload


@dataclass(frozen=True)
class TrajectoryEntry:
    """A single event in the agent reasoning/tool/finding timeline."""

    entry_type: Literal["think", "tool_call", "tool_response", "finding"]
    content: str


def normalize_cwe_id(raw_cwe: str) -> str:
    """Lenient CWE normalization for model output."""
    return _strict_normalize_cwe_id(raw_cwe, strict=False)


def _normalize_finding_path(raw_path: str) -> str:
    path = raw_path.strip().replace("\\", "/")
    if not path:
        return path
    return posixpath.normpath(path)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by canonical file path and exact CWE scope.

    Uses the internal score to choose between duplicates and sort output.
    """
    kept_by_key: dict[tuple[str, tuple[str, ...]], Finding] = {}

    for finding in findings:
        finding.file_path = _normalize_finding_path(finding.file_path)
        finding.cwe_ids = list(dict.fromkeys(normalize_cwe_id(c) for c in finding.cwe_ids))
        key = (finding.file_path, tuple(sorted(finding.cwe_ids)))
        existing = kept_by_key.get(key)
        if existing is None or finding.confidence > existing.confidence:
            kept_by_key[key] = finding

    kept = list(kept_by_key.values())
    kept.sort(key=finding_sort_key)
    return kept


def finding_sort_key(finding: Finding) -> tuple[str, bool, int, str, str]:
    """Order findings by CWE scope, then the model's local submission rank."""
    return (
        finding.cwe_ids[0] if finding.cwe_ids else "",
        finding.submission_rank is None,
        finding.submission_rank or 0,
        finding.file_path,
        finding.title,
    )
