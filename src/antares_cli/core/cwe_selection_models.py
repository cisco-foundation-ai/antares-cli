# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared models for repository-aware CWE selection."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from antares_cli.core.cwe_selection_limits import DEFAULT_AUTOMATIC_CWE_LIMIT
from antares_cli.core.cwe_selection_scopes import ScanScope as ScanScope

CweAbstractionLevel = Literal["all", "pillar", "class", "base", "variant", "compound"]
SelectionMode = Literal["auto", "explicit"]


@dataclass(slots=True, frozen=True)
class RepositoryProfile:
    """Static repository evidence used to plan security coverage."""

    root: Path
    languages: dict[str, float]
    frameworks: tuple[str, ...] = ()
    package_managers: tuple[str, ...] = ()
    dependency_files: tuple[str, ...] = ()
    route_files: tuple[str, ...] = ()
    auth_signals: tuple[str, ...] = ()
    data_store_signals: tuple[str, ...] = ()
    template_signals: tuple[str, ...] = ()
    file_io_signals: tuple[str, ...] = ()
    network_client_signals: tuple[str, ...] = ()
    deserialization_signals: tuple[str, ...] = ()
    crypto_signals: tuple[str, ...] = ()
    native_code_signals: tuple[str, ...] = ()
    iac_signals: tuple[str, ...] = ()
    secret_signals: tuple[str, ...] = ()
    request_input_signals: tuple[str, ...] = ()
    upload_signals: tuple[str, ...] = ()
    logging_signals: tuple[str, ...] = ()
    parser_signals: tuple[str, ...] = ()
    configuration_signals: tuple[str, ...] = ()
    cwe_evidence: dict[str, tuple[str, ...]] = field(default_factory=dict)
    cwe_evidence_files: dict[str, tuple[str, ...]] = field(default_factory=dict)
    cwe_evidence_scores: dict[str, int] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root.name,
            "languages": self.languages,
            "frameworks": list(self.frameworks),
            "package_managers": list(self.package_managers),
            "dependency_files": list(self.dependency_files),
            "route_files": list(self.route_files),
            "auth_signals": list(self.auth_signals),
            "data_store_signals": list(self.data_store_signals),
            "template_signals": list(self.template_signals),
            "file_io_signals": list(self.file_io_signals),
            "network_client_signals": list(self.network_client_signals),
            "deserialization_signals": list(self.deserialization_signals),
            "crypto_signals": list(self.crypto_signals),
            "native_code_signals": list(self.native_code_signals),
            "iac_signals": list(self.iac_signals),
            "secret_signals": list(self.secret_signals),
            "request_input_signals": list(self.request_input_signals),
            "upload_signals": list(self.upload_signals),
            "logging_signals": list(self.logging_signals),
            "parser_signals": list(self.parser_signals),
            "configuration_signals": list(self.configuration_signals),
            "cwe_evidence": {
                cwe_id: list(evidence) for cwe_id, evidence in self.cwe_evidence.items()
            },
            "cwe_evidence_files": {
                cwe_id: list(files) for cwe_id, files in self.cwe_evidence_files.items()
            },
            "cwe_evidence_scores": self.cwe_evidence_scores,
            "confidence": self.confidence,
        }


@dataclass(slots=True, frozen=True)
class ScanIntent:
    scope: ScanScope = "auto"
    cwe_level: CweAbstractionLevel = "all"
    mode: SelectionMode = "auto"


@dataclass(slots=True, frozen=True)
class SelectedCheck:
    check_id: str
    title: str
    cwe_ids: tuple[str, ...]
    score: float
    reasons: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    worker_group: str | None = None
    plain_language_summary: str = ""
    why_it_matters: str = ""
    selection_tier: str = ""
    repository_evidence_score: int = 0
    repository_specific_evidence_score: int = 0
    repository_category_evidence_score: int = 0
    repository_relationship_evidence_score: int = 0
    repository_evidence_coverage: int = 0
    taxonomy_priority_score: int = 0
    ranking_score: int = 0
    exact_platform_match: bool = False
    concrete_language_mismatch: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "cwe_ids": list(self.cwe_ids),
            "score": self.score,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "worker_group": self.worker_group,
            "plain_language_summary": self.plain_language_summary,
            "why_it_matters": self.why_it_matters,
            "selection_tier": self.selection_tier,
            "repository_evidence_score": self.repository_evidence_score,
            "repository_specific_evidence_score": self.repository_specific_evidence_score,
            "repository_category_evidence_score": self.repository_category_evidence_score,
            "repository_relationship_evidence_score": self.repository_relationship_evidence_score,
            "repository_evidence_coverage": self.repository_evidence_coverage,
            "taxonomy_priority_score": self.taxonomy_priority_score,
            "ranking_score": self.ranking_score,
            "exact_platform_match": self.exact_platform_match,
            "concrete_language_mismatch": self.concrete_language_mismatch,
        }


@dataclass(slots=True, frozen=True)
class ExcludedCheck:
    check_id: str
    title: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "reasons": list(self.reasons),
        }


@dataclass(slots=True, frozen=True)
class CweSelectionRequest:
    target: Path
    cwe_ids: list[str] = field(default_factory=list)
    ignore_paths: tuple[str, ...] = ()
    allow_sensitive_files: tuple[str, ...] = ()
    scope: ScanScope = "auto"
    cwe_level: CweAbstractionLevel = "all"
    max_cwes: int = DEFAULT_AUTOMATIC_CWE_LIMIT


@dataclass(slots=True, frozen=True)
class CweSelectionPlan:
    profile: RepositoryProfile
    intent: ScanIntent
    selected_checks: tuple[SelectedCheck, ...]
    explicit_cwe_ids: tuple[str, ...] = ()
    excluded_checks: tuple[ExcludedCheck, ...] = ()
    selection_policy: str = "mitre_cwe_comprehensive"
    automatic_limit: int | None = None
    candidate_cwe_count: int = 0
    selection_notes: tuple[str, ...] = ()
    priority_baseline_name: str | None = None
    priority_baseline_eligible_count: int = 0
    priority_baseline_selected_count: int = 0
    taxonomy_metadata: dict[str, object] | None = None

    def cwe_ids(self) -> list[str]:
        selected_ids: list[str] = []
        seen: set[str] = set()
        for check in self.selected_checks:
            for cwe_id in check.cwe_ids:
                if cwe_id not in seen:
                    selected_ids.append(cwe_id)
                    seen.add(cwe_id)
        return selected_ids

    def to_dict(self) -> dict[str, object]:
        omitted_candidate_count = max(0, self.candidate_cwe_count - len(self.cwe_ids()))
        selection_tier_counts: dict[str, int] = {}
        for check in self.selected_checks:
            if check.selection_tier:
                selection_tier_counts[check.selection_tier] = (
                    selection_tier_counts.get(check.selection_tier, 0) + 1
                )
        priority_baseline = None
        if self.priority_baseline_name is not None:
            priority_baseline = {
                "name": self.priority_baseline_name,
                "eligible_count": self.priority_baseline_eligible_count,
                "selected_count": self.priority_baseline_selected_count,
            }
        return {
            "profile": self.profile.to_dict(),
            "intent": {
                "scope": self.intent.scope,
                "cwe_level": self.intent.cwe_level,
                "mode": self.intent.mode,
            },
            "selection_policy": self.selection_policy,
            "selection_notes": list(self.selection_notes),
            "selection_tier_counts": selection_tier_counts,
            "taxonomy": self.taxonomy_metadata,
            "priority_baseline": priority_baseline,
            "automatic_limit": self.automatic_limit,
            "candidate_cwe_count": self.candidate_cwe_count,
            "omitted_candidate_count": omitted_candidate_count,
            "truncated": omitted_candidate_count > 0,
            "selected_checks": [check.to_dict() for check in self.selected_checks],
            "selected_cwe_ids": self.cwe_ids(),
            "explicit_cwe_ids": list(self.explicit_cwe_ids),
            "excluded_checks": [check.to_dict() for check in self.excluded_checks],
        }
