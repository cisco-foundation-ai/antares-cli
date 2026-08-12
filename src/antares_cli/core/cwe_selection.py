# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository-aware selection of CWE-backed security checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from antares_cli.core.cwe import normalize_cwe_ids
from antares_cli.core.cwe_selection_limits import resolve_automatic_cwe_limit
from antares_cli.core.cwe_selection_models import (
    CweAbstractionLevel,
    CweSelectionPlan,
    CweSelectionRequest,
    ExcludedCheck,
    RepositoryProfile,
    ScanIntent,
    ScanScope,
    SelectedCheck,
)
from antares_cli.core.cwe_selection_profile import RepositoryProfiler
from antares_cli.core.cwe_selection_relevance import (
    auto_selection_reasons,
    has_concrete_language_mismatch,
    has_exact_platform_match,
)
from antares_cli.core.cwe_selection_relevance import (
    exclusion_reason as cwe_exclusion_reason,
)
from antares_cli.core.cwe_selection_scopes import (
    CURRENT_OWASP_VIEW_ID,
    CURRENT_TOP_25_VIEW_ID,
    normalize_scan_scope,
)
from antares_cli.knowledge.cwe_database import CweDatabase, CweEntry

__all__ = [
    "CweAbstractionLevel",
    "CweSelectionPlan",
    "CweSelectionRequest",
    "CweSelectionService",
    "ExcludedCheck",
    "RepositoryProfile",
    "RepositoryProfiler",
    "ScanIntent",
    "ScanScope",
    "SelectedCheck",
]

_AUTOMATIC_SELECTION_POLICY = "mitre_mode_aware_repository_relevance_v6"
_EXPLICIT_SELECTION_POLICY = "explicit_cwe_ids"
_SIMPLIFIED_MAPPING_VIEW = "CWE-1003"
_SOFTWARE_DEVELOPMENT_VIEW = "CWE-699"
_CURRENT_TOP_25_BASELINE_NAME = "MITRE CWE Top 25 (CWE-1435)"
_AUTO_RELATIONSHIP_FAMILY_CAP = 2
_COMMON_AUTOMATIC_SELECTION_NOTES = (
    "Platform mismatches affect rank rather than eligibility.",
    "Repository-specific slots prefer direct source evidence, then category evidence, then "
    "MITRE relationship expansion; test and generated-code evidence is retained at lower weight.",
    "Remaining tie-breakers are exact platform matches, CVE mapping guidance, abstraction, "
    "exploit likelihood, and status.",
)
_EXPLICIT_SELECTION_NOTES = (
    "Exact user-supplied CWE IDs are preserved in request order; automatic limits and filters "
    "do not apply.",
)
_PROFILE_SIGNAL_RULES = (
    (
        "authentication",
        "auth_signals",
        frozenset(
            {
                "CWE-250",
                "CWE-269",
                "CWE-284",
                "CWE-285",
                "CWE-287",
                "CWE-306",
                "CWE-307",
                "CWE-384",
                "CWE-521",
                "CWE-640",
                "CWE-862",
                "CWE-863",
            }
        ),
    ),
    (
        "data-store",
        "data_store_signals",
        frozenset({"CWE-20", "CWE-74", "CWE-89", "CWE-200", "CWE-943"}),
    ),
    (
        "template-rendering",
        "template_signals",
        frozenset({"CWE-20", "CWE-74", "CWE-79", "CWE-116"}),
    ),
    (
        "file-I/O",
        "file_io_signals",
        frozenset(
            {
                "CWE-22",
                "CWE-73",
                "CWE-200",
                "CWE-400",
                "CWE-404",
                "CWE-434",
                "CWE-459",
                "CWE-552",
                "CWE-668",
                "CWE-772",
            }
        ),
    ),
    (
        "outbound-network",
        "network_client_signals",
        frozenset(
            {
                "CWE-200",
                "CWE-295",
                "CWE-319",
                "CWE-346",
                "CWE-400",
                "CWE-404",
                "CWE-770",
                "CWE-772",
                "CWE-918",
            }
        ),
    ),
    (
        "deserialization",
        "deserialization_signals",
        frozenset({"CWE-20", "CWE-400", "CWE-502", "CWE-913"}),
    ),
    (
        "cryptography",
        "crypto_signals",
        frozenset(
            {
                "CWE-295",
                "CWE-321",
                "CWE-327",
                "CWE-328",
                "CWE-330",
                "CWE-345",
                "CWE-347",
            }
        ),
    ),
    (
        "native-memory",
        "native_code_signals",
        frozenset(
            {
                "CWE-119",
                "CWE-120",
                "CWE-121",
                "CWE-122",
                "CWE-123",
                "CWE-124",
                "CWE-125",
                "CWE-126",
                "CWE-127",
                "CWE-131",
                "CWE-190",
                "CWE-401",
                "CWE-415",
                "CWE-416",
                "CWE-457",
                "CWE-476",
                "CWE-787",
            }
        ),
    ),
    (
        "infrastructure-as-code",
        "iac_signals",
        frozenset(
            {
                "CWE-15",
                "CWE-16",
                "CWE-250",
                "CWE-269",
                "CWE-276",
                "CWE-284",
                "CWE-732",
                "CWE-798",
            }
        ),
    ),
    (
        "credential/secret",
        "secret_signals",
        frozenset({"CWE-200", "CWE-312", "CWE-319", "CWE-522", "CWE-532", "CWE-798", "CWE-922"}),
    ),
    (
        "request-input",
        "request_input_signals",
        frozenset(
            {
                "CWE-20",
                "CWE-74",
                "CWE-77",
                "CWE-78",
                "CWE-79",
                "CWE-89",
                "CWE-94",
                "CWE-95",
                "CWE-113",
                "CWE-177",
                "CWE-184",
                "CWE-235",
                "CWE-284",
                "CWE-352",
                "CWE-400",
                "CWE-601",
                "CWE-770",
                "CWE-862",
                "CWE-863",
            }
        ),
    ),
    (
        "file-upload",
        "upload_signals",
        frozenset({"CWE-20", "CWE-22", "CWE-400", "CWE-409", "CWE-434", "CWE-770"}),
    ),
    (
        "web-endpoint",
        "route_files",
        frozenset(
            {
                "CWE-20",
                "CWE-79",
                "CWE-200",
                "CWE-287",
                "CWE-352",
                "CWE-400",
                "CWE-601",
                "CWE-770",
                "CWE-862",
                "CWE-863",
            }
        ),
    ),
    (
        "logging",
        "logging_signals",
        frozenset({"CWE-117", "CWE-200", "CWE-532"}),
    ),
    (
        "structured-parser",
        "parser_signals",
        frozenset({"CWE-20", "CWE-400", "CWE-674", "CWE-770", "CWE-1286", "CWE-1287"}),
    ),
    (
        "external-configuration",
        "configuration_signals",
        frozenset({"CWE-15", "CWE-16", "CWE-200", "CWE-269", "CWE-732", "CWE-798", "CWE-922"}),
    ),
)
_PRIMARY_PROFILE_SIGNAL_CWE_IDS = {
    "auth_signals": frozenset(
        {
            "CWE-284",
            "CWE-287",
            "CWE-306",
            "CWE-307",
            "CWE-384",
            "CWE-521",
            "CWE-640",
        }
    ),
    "data_store_signals": frozenset({"CWE-89", "CWE-200", "CWE-943"}),
    "template_signals": frozenset({"CWE-79", "CWE-116"}),
    "file_io_signals": frozenset({"CWE-22", "CWE-73", "CWE-434"}),
    "network_client_signals": frozenset({"CWE-295", "CWE-319", "CWE-918"}),
    "deserialization_signals": frozenset({"CWE-502"}),
    "crypto_signals": frozenset({"CWE-321", "CWE-327", "CWE-328", "CWE-330"}),
    "native_code_signals": frozenset(
        {"CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-416", "CWE-476", "CWE-787"}
    ),
    "iac_signals": frozenset({"CWE-16", "CWE-276", "CWE-732", "CWE-798"}),
    "secret_signals": frozenset({"CWE-312", "CWE-319", "CWE-522", "CWE-798"}),
    "request_input_signals": frozenset(
        {"CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"}
    ),
    "upload_signals": frozenset({"CWE-22", "CWE-434"}),
    "logging_signals": frozenset({"CWE-117", "CWE-532"}),
    "parser_signals": frozenset({"CWE-20", "CWE-1286"}),
    "configuration_signals": frozenset({"CWE-15", "CWE-16"}),
}
_FRAMEWORK_PROFILE_SIGNAL_RULES = (
    (
        "web-application framework",
        frozenset(
            {
                "django",
                "echo",
                "express",
                "fastapi",
                "fiber",
                "flask",
                "gin",
                "gorilla",
                "grpc",
                "hapi",
                "jetty",
                "koa",
                "micronaut",
                "netty",
                "nestjs",
                "next",
                "quarkus",
                "rails",
                "resteasy",
                "spring",
                "tomcat",
                "undertow",
                "vaadin",
                "vertx",
            }
        ),
        frozenset(
            {
                "CWE-20",
                "CWE-79",
                "CWE-287",
                "CWE-400",
                "CWE-862",
            }
        ),
        50,
    ),
    (
        "web-application related surface",
        frozenset(
            {
                "django",
                "echo",
                "express",
                "fastapi",
                "fiber",
                "flask",
                "gin",
                "gorilla",
                "grpc",
                "hapi",
                "jetty",
                "koa",
                "micronaut",
                "netty",
                "nestjs",
                "next",
                "quarkus",
                "rails",
                "resteasy",
                "spring",
                "tomcat",
                "undertow",
                "vaadin",
                "vertx",
            }
        ),
        frozenset({"CWE-200", "CWE-352", "CWE-601", "CWE-770", "CWE-863"}),
        40,
    ),
    (
        "event-driven server resource surface",
        frozenset({"grpc", "netty", "undertow", "vertx"}),
        frozenset({"CWE-400", "CWE-404", "CWE-770", "CWE-772"}),
        50,
    ),
    (
        "browser-interface framework",
        frozenset({"next", "react"}),
        frozenset({"CWE-79", "CWE-116", "CWE-451"}),
        40,
    ),
)


class CweSelectionService:
    """Selects comprehensive MITRE CWE scan targets for a repository."""

    def __init__(
        self,
        *,
        cwe_database: CweDatabase | None = None,
        profiler: RepositoryProfiler | None = None,
    ) -> None:
        self._cwe_database = cwe_database or CweDatabase.load_default()
        self._profiler = profiler or RepositoryProfiler()
        self._children_by_parent, self._parents_by_child = _relationship_graph(
            self._cwe_database.list_all()
        )

    def select(self, request: CweSelectionRequest) -> CweSelectionPlan:
        request = replace(request, scope=normalize_scan_scope(request.scope))
        profile = self._profiler.profile(
            request.target,
            ignore_paths=request.ignore_paths,
            allow_sensitive_files=request.allow_sensitive_files,
        )
        if request.cwe_ids:
            return self._explicit_plan(request, profile)
        return self._auto_plan(request, profile)

    def _explicit_plan(
        self,
        request: CweSelectionRequest,
        profile: RepositoryProfile,
    ) -> CweSelectionPlan:
        cwe_ids = tuple(normalize_cwe_ids(request.cwe_ids, self._cwe_database))
        selected = tuple(
            _selected_check_for_entry(
                self._entry_for_cwe_id(cwe_id),
                profile=profile,
                score=1.0,
                confidence=1.0,
                reasons=("Explicitly requested by user",),
            )
            for cwe_id in cwe_ids
        )
        return CweSelectionPlan(
            profile=profile,
            intent=ScanIntent(scope=request.scope, cwe_level="all", mode="explicit"),
            selected_checks=selected,
            explicit_cwe_ids=cwe_ids,
            selection_policy=_EXPLICIT_SELECTION_POLICY,
            candidate_cwe_count=len(cwe_ids),
            selection_notes=_EXPLICIT_SELECTION_NOTES,
            taxonomy_metadata=_taxonomy_metadata(self._cwe_database),
        )

    def _auto_plan(
        self,
        request: CweSelectionRequest,
        profile: RepositoryProfile,
    ) -> CweSelectionPlan:
        selected: list[SelectedCheck] = []
        excluded: list[ExcludedCheck] = []
        relationship_evidence = self._relationship_evidence(profile)
        for entry in self._cwe_database.list_all():
            level_reason = _level_exclusion_reason(entry, request.cwe_level)
            if level_reason is not None:
                excluded.append(
                    ExcludedCheck(
                        check_id=_check_id(entry),
                        title=entry.name,
                        reasons=(level_reason,),
                    )
                )
                continue
            exclusion_reason = cwe_exclusion_reason(entry, profile, request.scope)
            if exclusion_reason is not None:
                excluded.append(
                    ExcludedCheck(
                        check_id=_check_id(entry),
                        title=entry.name,
                        reasons=(exclusion_reason,),
                    )
                )
                continue
            selected.append(
                _auto_selected_check(
                    entry,
                    profile,
                    request.scope,
                    relationship_evidence=relationship_evidence.get(entry.id),
                )
            )
        selected.sort(
            key=_auto_relevance_sort_key if request.scope == "auto" else _ranked_check_sort_key
        )
        automatic_limit = resolve_automatic_cwe_limit(request.max_cwes)
        selected_checks = self._select_portfolio(
            selected,
            automatic_limit=automatic_limit,
            scope=request.scope,
            profile=profile,
        )
        return CweSelectionPlan(
            profile=profile,
            intent=ScanIntent(scope=request.scope, cwe_level=request.cwe_level, mode="auto"),
            selected_checks=selected_checks,
            excluded_checks=tuple(excluded),
            selection_policy=_AUTOMATIC_SELECTION_POLICY,
            automatic_limit=automatic_limit,
            candidate_cwe_count=len(selected),
            selection_notes=_automatic_selection_notes(request.scope, profile),
            priority_baseline_name=(
                None if request.scope == "auto" else _CURRENT_TOP_25_BASELINE_NAME
            ),
            priority_baseline_eligible_count=(
                0
                if request.scope == "auto"
                else sum(_is_current_top_25_check(check, self._cwe_database) for check in selected)
            ),
            priority_baseline_selected_count=(
                0
                if request.scope == "auto"
                else sum(
                    _is_current_top_25_check(check, self._cwe_database) for check in selected_checks
                )
            ),
            taxonomy_metadata=_taxonomy_metadata(self._cwe_database),
        )

    def _relationship_evidence(
        self,
        profile: RepositoryProfile,
    ) -> dict[str, tuple[str, int]]:
        evidence: dict[str, tuple[str, int]] = {}
        for seed_id in sorted(_profile_evidence_seed_ids(profile)):
            for child_id in sorted(self._children_by_parent.get(seed_id, ())):
                _record_relationship_evidence(evidence, child_id, seed_id, 45)
                for grandchild_id in sorted(self._children_by_parent.get(child_id, ())):
                    _record_relationship_evidence(evidence, grandchild_id, seed_id, 25)
            for parent_id in sorted(self._parents_by_child.get(seed_id, ())):
                _record_relationship_evidence(evidence, parent_id, seed_id, 20)
        return evidence

    def _select_portfolio(
        self,
        ranked: list[SelectedCheck],
        *,
        automatic_limit: int,
        scope: ScanScope,
        profile: RepositoryProfile,
    ) -> tuple[SelectedCheck, ...]:
        if scope == "auto":
            return self._select_auto_relevance_portfolio(ranked, automatic_limit=automatic_limit)

        repository_quota = _repository_specific_quota(automatic_limit)
        baseline_quota = automatic_limit - repository_quota
        repository_specific = sorted(
            (
                check
                for check in ranked
                if check.repository_evidence_score > 0
                and not _is_current_top_25_check(check, self._cwe_database)
            ),
            key=_repository_specific_sort_key,
        )
        baseline = [
            check
            for check in ranked
            if _is_priority_baseline_check(
                check,
                self._cwe_database,
                profile,
            )
        ]
        chosen: list[SelectedCheck] = []
        chosen_ids: set[str] = set()
        _extend_unique_checks(
            chosen,
            chosen_ids,
            repository_specific[:repository_quota],
            tier="repository-specific",
        )
        _extend_unique_checks(
            chosen,
            chosen_ids,
            baseline[:baseline_quota],
            tier="priority-baseline",
        )
        _extend_unique_checks(
            chosen,
            chosen_ids,
            baseline,
            tier="priority-baseline",
            limit=automatic_limit,
        )
        _extend_unique_checks(
            chosen,
            chosen_ids,
            ranked,
            tier="ranked-fill",
            limit=automatic_limit,
        )
        return tuple(chosen[:automatic_limit])

    def _select_auto_relevance_portfolio(
        self,
        ranked: list[SelectedCheck],
        *,
        automatic_limit: int,
    ) -> tuple[SelectedCheck, ...]:
        chosen: list[SelectedCheck] = []
        deferred: list[SelectedCheck] = []
        family_counts: dict[str, int] = defaultdict(int)
        for check in ranked:
            family_ids = self._relationship_family_ids(check.cwe_ids[0])
            has_direct_or_category_evidence = bool(
                check.repository_specific_evidence_score or check.repository_category_evidence_score
            )
            if not has_direct_or_category_evidence and any(
                family_counts[family_id] >= _AUTO_RELATIONSHIP_FAMILY_CAP
                for family_id in family_ids
            ):
                deferred.append(check)
                continue
            chosen.append(_with_auto_relevance_tier(check))
            for family_id in family_ids:
                family_counts[family_id] += 1
            if len(chosen) >= automatic_limit:
                return tuple(chosen)
        for check in deferred:
            chosen.append(_with_auto_relevance_tier(check))
            if len(chosen) >= automatic_limit:
                break
        return tuple(chosen)

    def _relationship_family_ids(self, cwe_id: str) -> set[str]:
        family_ids = {cwe_id}
        direct_parents = self._parents_by_child.get(cwe_id, set())
        family_ids.update(direct_parents)
        for parent_id in direct_parents:
            family_ids.update(self._parents_by_child.get(parent_id, set()))
        return family_ids

    def _entry_for_cwe_id(self, cwe_id: str) -> CweEntry:
        entry = self._cwe_database.get_by_id(cwe_id)
        if entry is None:
            raise ValueError(f"Unknown CWE ID after normalization: {cwe_id}")
        return entry


def _automatic_selection_notes(
    scope: ScanScope,
    profile: RepositoryProfile,
) -> tuple[str, ...]:
    mode_notes: tuple[str, ...]
    if scope == "top25":
        mode_notes = (
            "Top25 mode restricts eligibility to the current official MITRE CWE Top 25.",
            "The automatic limit may select a smaller prefix; the default limit selects all 25.",
        )
    elif scope == "owasp":
        mode_notes = (
            "OWASP mode restricts eligibility to the current MITRE OWASP Top Ten view.",
            "The bounded portfolio reserves about three eighths for repository-specific coverage "
            "within that view and preserves eligible Top 25 coverage, then backfills by rank.",
        )
    else:
        mode_notes = (
            "The default auto mode excludes only deprecated CWEs and requested abstraction "
            "mismatches from the full catalog.",
            "Auto ranking uses direct rule precision, independent-file coverage, category "
            "evidence, CWE relationships, and repository platform matches in that order.",
            "Large repositories reserve profile capacity for security-sensitive source paths "
            "before deterministic component/language sampling.",
            "MITRE Top 25 membership is neither a ranking signal nor a reserved quota in auto mode.",
            "For relationship-only and evidence-free candidates, the first pass admits at most "
            "two checks from one parent/ancestor family before backfilling; direct and category "
            "evidence is never suppressed by this diversity rule.",
        )
        if not _profile_evidence_seed_ids(profile):
            mode_notes = (
                *mode_notes,
                "The repository produced no direct or category security evidence; this plan is "
                "low confidence and relies on platform matches plus neutral taxonomy tie-breakers.",
            )
    return (*mode_notes, *_COMMON_AUTOMATIC_SELECTION_NOTES)


def _auto_selected_check(
    entry: CweEntry,
    profile: RepositoryProfile,
    scope: ScanScope,
    *,
    relationship_evidence: tuple[str, int] | None,
) -> SelectedCheck:
    exact_platform_match = has_exact_platform_match(entry, profile)
    language_mismatch = has_concrete_language_mismatch(entry, profile)
    category_signal_labels, category_signal_files, category_evidence_score = (
        _matching_profile_signals(entry, profile)
    )
    exact_signal_labels = profile.cwe_evidence.get(entry.id, ())
    exact_signal_files = profile.cwe_evidence_files.get(entry.id, ())
    signal_labels = (*category_signal_labels, *exact_signal_labels)
    evidence_coverage = len(set(category_signal_files) | set(exact_signal_files))
    relationship_reason, relationship_score = relationship_evidence or ("", 0)
    exact_evidence_score = profile.cwe_evidence_scores.get(entry.id, 0)
    direct_evidence_score = min(
        140,
        max(category_evidence_score, exact_evidence_score)
        + (10 if category_evidence_score and exact_evidence_score else 0),
    )
    repository_evidence_score = direct_evidence_score + relationship_score
    taxonomy_priority_score = _taxonomy_priority_score(entry, scope=scope)
    ranking_score = _automatic_ranking_score(
        exact_platform_match=exact_platform_match,
        repository_evidence_score=repository_evidence_score,
        taxonomy_priority_score=taxonomy_priority_score,
        language_mismatch=language_mismatch,
    )
    reasons = (
        *auto_selection_reasons(entry, scope, exact_platform_match),
        *_taxonomy_priority_reasons(entry),
        *(f"Repository {label} evidence supports this CWE" for label in signal_labels),
        *(
            (f"Repository evidence spans {evidence_coverage} independently sampled files",)
            if evidence_coverage > 1
            else ()
        ),
        *((relationship_reason,) if relationship_reason else ()),
        *(
            ("MITRE concrete language examples do not match; retained for ranking",)
            if language_mismatch
            else ()
        ),
    )
    return _selected_check_for_entry(
        entry,
        profile=profile,
        score=max(0.0, min(ranking_score / 250, 1.0)),
        confidence=_relevance_confidence(
            exact_evidence_score=exact_evidence_score,
            category_evidence_score=category_evidence_score,
            relationship_evidence_score=relationship_score,
            exact_platform_match=exact_platform_match,
            language_mismatch=language_mismatch,
        ),
        reasons=reasons,
        repository_evidence_score=repository_evidence_score,
        repository_specific_evidence_score=exact_evidence_score,
        repository_category_evidence_score=category_evidence_score,
        repository_relationship_evidence_score=relationship_score,
        repository_evidence_coverage=evidence_coverage,
        taxonomy_priority_score=taxonomy_priority_score,
        ranking_score=ranking_score,
        exact_platform_match=exact_platform_match,
        concrete_language_mismatch=language_mismatch,
    )


def _taxonomy_priority_score(
    entry: CweEntry,
    *,
    scope: ScanScope,
) -> int:
    priority = 0
    if scope != "auto" and CURRENT_TOP_25_VIEW_ID in entry.view_ids:
        priority += 100
    if _SIMPLIFIED_MAPPING_VIEW in entry.view_ids:
        priority += 20
    if scope != "auto" and CURRENT_OWASP_VIEW_ID in entry.view_ids:
        priority += 10
    if _SOFTWARE_DEVELOPMENT_VIEW in entry.view_ids:
        priority += 5
    priority += {"Allowed": 5, "Allowed-with-Review": 3}.get(entry.mapping_usage, 0)
    priority += {"Base": 4, "Variant": 3, "Compound": 2, "Class": 1}.get(
        entry.abstraction,
        0,
    )
    priority += {"High": 4, "Medium": 2, "Low": 1}.get(entry.likelihood_of_exploit, 0)
    if entry.status == "Stable":
        priority += 3
    return priority


def _automatic_ranking_score(
    *,
    exact_platform_match: bool,
    repository_evidence_score: int,
    taxonomy_priority_score: int,
    language_mismatch: bool,
) -> int:
    priority = repository_evidence_score + taxonomy_priority_score
    if exact_platform_match:
        priority += 30
    if language_mismatch:
        priority -= 80
    return max(0, priority)


def _relevance_confidence(
    *,
    exact_evidence_score: int,
    category_evidence_score: int,
    relationship_evidence_score: int,
    exact_platform_match: bool,
    language_mismatch: bool,
) -> float:
    if exact_evidence_score > 0:
        return 0.9
    if category_evidence_score > 0:
        return 0.75
    if relationship_evidence_score > 0:
        return 0.6
    if exact_platform_match:
        return 0.5
    if language_mismatch:
        return 0.15
    return 0.3


def _matching_profile_signals(
    entry: CweEntry,
    profile: RepositoryProfile,
) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    labels: list[str] = []
    files: set[str] = set()
    scores: list[int] = []
    for label, profile_field, cwe_ids in _PROFILE_SIGNAL_RULES:
        signal_files = getattr(profile, profile_field)
        if signal_files and entry.id in cwe_ids:
            labels.append(label)
            files.update(signal_files)
            scores.append(
                50 if entry.id in _PRIMARY_PROFILE_SIGNAL_CWE_IDS.get(profile_field, ()) else 40
            )
    for label, frameworks, cwe_ids, framework_score in _FRAMEWORK_PROFILE_SIGNAL_RULES:
        if set(profile.frameworks) & frameworks and entry.id in cwe_ids:
            labels.append(label)
            files.update(profile.dependency_files)
            scores.append(framework_score)
    score = min(60, max(scores) + (len(scores) - 1) * 5) if scores else 0
    return tuple(labels), tuple(sorted(files)), score


def _profile_evidence_seed_ids(profile: RepositoryProfile) -> set[str]:
    category_seed_ids = {
        cwe_id
        for _label, profile_field, cwe_ids in _PROFILE_SIGNAL_RULES
        if getattr(profile, profile_field)
        for cwe_id in cwe_ids
    }
    framework_seed_ids = {
        cwe_id
        for _label, frameworks, cwe_ids, _score in _FRAMEWORK_PROFILE_SIGNAL_RULES
        if set(profile.frameworks) & frameworks
        for cwe_id in cwe_ids
    }
    return category_seed_ids | framework_seed_ids | set(profile.cwe_evidence)


def _taxonomy_priority_reasons(entry: CweEntry) -> tuple[str, ...]:
    reasons: list[str] = []
    if CURRENT_TOP_25_VIEW_ID in entry.view_ids:
        reasons.append("Member of the current MITRE CWE Top 25")
    if _SIMPLIFIED_MAPPING_VIEW in entry.view_ids:
        reasons.append("Member of MITRE's simplified vulnerability-mapping view")
    if CURRENT_OWASP_VIEW_ID in entry.view_ids:
        reasons.append("Member of the current MITRE OWASP Top Ten view")
    if entry.mapping_usage:
        if entry.mapping_usage in {"Allowed", "Allowed-with-Review"}:
            reasons.append(
                f"MITRE CVE mapping usage is {entry.mapping_usage} (positive ranking signal)"
            )
        else:
            reasons.append(
                f"MITRE CVE mapping usage is {entry.mapping_usage}; retained because mapping "
                "guidance does not determine scan applicability"
            )
    return tuple(reasons)


def _entry_view_ids(check: SelectedCheck, cwe_database: CweDatabase) -> list[str]:
    entry = cwe_database.get_by_id(check.cwe_ids[0])
    return entry.view_ids if entry is not None else []


def _is_current_top_25_check(check: SelectedCheck, cwe_database: CweDatabase) -> bool:
    return CURRENT_TOP_25_VIEW_ID in _entry_view_ids(check, cwe_database)


def _is_priority_baseline_check(
    check: SelectedCheck,
    cwe_database: CweDatabase,
    profile: RepositoryProfile,
) -> bool:
    if not _is_current_top_25_check(check, cwe_database):
        return False
    if check.repository_evidence_score > 0:
        return True
    entry = cwe_database.get_by_id(check.cwe_ids[0])
    return entry is not None and not has_concrete_language_mismatch(entry, profile)


def _auto_relevance_sort_key(
    check: SelectedCheck,
) -> tuple[int, int, int, int, int, int, int, int, int, int, int]:
    evidence_class = (
        0
        if check.repository_specific_evidence_score > 0
        else 1
        if check.repository_category_evidence_score > 0
        else 2
        if check.repository_relationship_evidence_score > 0
        else 3
        if check.exact_platform_match
        else 5
        if check.concrete_language_mismatch
        else 4
    )
    return (
        evidence_class,
        -check.repository_specific_evidence_score,
        -(
            check.repository_category_evidence_score
            if not check.repository_specific_evidence_score
            else 0
        ),
        -check.repository_evidence_coverage,
        -check.repository_category_evidence_score,
        -check.repository_relationship_evidence_score,
        -int(check.exact_platform_match),
        int(check.concrete_language_mismatch),
        -check.taxonomy_priority_score,
        -check.ranking_score,
        _cwe_number(check),
    )


def _ranked_check_sort_key(check: SelectedCheck) -> tuple[int, int]:
    ranking_score = check.ranking_score or round(check.score * 250)
    return (-ranking_score, _cwe_number(check))


def _repository_specific_sort_key(
    check: SelectedCheck,
) -> tuple[int, int, int, int, int, int]:
    """Rank direct repository evidence before weaker taxonomy propagation."""
    evidence_class = (
        0
        if check.repository_specific_evidence_score > 0
        else 1
        if check.repository_category_evidence_score > 0
        else 2
    )
    ranked_score, cwe_number = _ranked_check_sort_key(check)
    return (
        evidence_class,
        -check.repository_specific_evidence_score,
        -check.repository_category_evidence_score,
        -check.repository_relationship_evidence_score,
        ranked_score,
        cwe_number,
    )


def _with_auto_relevance_tier(check: SelectedCheck) -> SelectedCheck:
    tier = "repository-specific" if check.repository_evidence_score > 0 else "ranked-fill"
    return replace(check, selection_tier=tier)


def _cwe_number(check: SelectedCheck) -> int:
    return int(check.cwe_ids[0].split("-", maxsplit=1)[1])


def _repository_specific_quota(automatic_limit: int) -> int:
    """Reserve about three eighths for repo evidence and the rest for broad coverage."""
    return max(1, automatic_limit * 3 // 8)


def _relationship_graph(
    entries: list[CweEntry],
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    known_ids = {entry.id for entry in entries}
    children_by_parent: dict[str, set[str]] = defaultdict(set)
    parents_by_child: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        for relationship in entry.related_weaknesses:
            if relationship.get("nature") != "ChildOf":
                continue
            parent_id = relationship.get("cwe_id", "")
            if parent_id not in known_ids:
                continue
            children_by_parent[parent_id].add(entry.id)
            parents_by_child[entry.id].add(parent_id)
    return dict(children_by_parent), dict(parents_by_child)


def _record_relationship_evidence(
    evidence: dict[str, tuple[str, int]],
    candidate_id: str,
    seed_id: str,
    score: int,
) -> None:
    existing = evidence.get(candidate_id)
    if existing is not None and existing[1] >= score:
        return
    evidence[candidate_id] = (
        f"MITRE CWE relationship connects this entry to evidence-backed {seed_id}",
        score,
    )


def _extend_unique_checks(
    chosen: list[SelectedCheck],
    chosen_ids: set[str],
    candidates: Iterable[SelectedCheck],
    *,
    tier: str,
    limit: int | None = None,
) -> None:
    for check in candidates:
        if limit is not None and len(chosen) >= limit:
            return
        check_id = check.cwe_ids[0]
        if check_id in chosen_ids:
            continue
        chosen.append(replace(check, selection_tier=tier))
        chosen_ids.add(check_id)


def _level_exclusion_reason(entry: CweEntry, cwe_level: CweAbstractionLevel) -> str | None:
    if cwe_level == "all":
        return None
    if entry.abstraction.lower() == cwe_level:
        return None
    return f"Excluded because MITRE abstraction is {entry.abstraction or 'unspecified'}, not {cwe_level}"


def _selected_check_for_entry(
    entry: CweEntry,
    *,
    profile: RepositoryProfile,
    score: float,
    confidence: float,
    reasons: tuple[str, ...],
    repository_evidence_score: int = 0,
    repository_specific_evidence_score: int = 0,
    repository_category_evidence_score: int = 0,
    repository_relationship_evidence_score: int = 0,
    repository_evidence_coverage: int = 0,
    taxonomy_priority_score: int = 0,
    ranking_score: int = 0,
    exact_platform_match: bool = False,
    concrete_language_mismatch: bool = False,
) -> SelectedCheck:
    return SelectedCheck(
        check_id=_check_id(entry),
        title=entry.name,
        cwe_ids=(entry.id,),
        score=score,
        reasons=reasons,
        evidence=_profile_evidence(profile),
        confidence=confidence,
        worker_group=_worker_group(entry),
        plain_language_summary=_compact_text(entry.description or entry.extended_description),
        why_it_matters=_why_it_matters(entry),
        repository_evidence_score=repository_evidence_score,
        repository_specific_evidence_score=repository_specific_evidence_score,
        repository_category_evidence_score=repository_category_evidence_score,
        repository_relationship_evidence_score=repository_relationship_evidence_score,
        repository_evidence_coverage=repository_evidence_coverage,
        taxonomy_priority_score=taxonomy_priority_score,
        ranking_score=ranking_score,
        exact_platform_match=exact_platform_match,
        concrete_language_mismatch=concrete_language_mismatch,
    )


def _profile_evidence(profile: RepositoryProfile) -> tuple[str, ...]:
    evidence = [
        *(f"language:{language}" for language in sorted(profile.languages)),
        *(f"framework:{framework}" for framework in profile.frameworks),
        *profile.route_files,
        *profile.dependency_files,
        *profile.data_store_signals,
        *profile.file_io_signals,
        *profile.iac_signals,
        *profile.secret_signals,
    ]
    return tuple(_dedupe(evidence)[:8])


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def _worker_group(entry: CweEntry) -> str | None:
    preferred_views = ("CWE-699", "CWE-1000", "CWE-677", "CWE-1194", "CWE-1448")
    for view_id in preferred_views:
        if view_id in entry.view_ids:
            index = entry.view_ids.index(view_id)
            return entry.view_names[index] if index < len(entry.view_names) else view_id
    return entry.view_names[0] if entry.view_names else entry.abstraction or None


def _why_it_matters(entry: CweEntry) -> str:
    if entry.common_consequences:
        rationale = _compact_text(
            "Potential consequences include " + "; ".join(entry.common_consequences)
        )
    elif entry.mapping_rationale:
        rationale = _compact_text(entry.mapping_rationale)
    else:
        rationale = _compact_text(entry.extended_description or entry.description)
    if entry.likelihood_of_exploit:
        rationale += f" (Likelihood of Exploit: {entry.likelihood_of_exploit})"
    return rationale


def _compact_text(value: str, *, max_length: int = 260) -> str:
    compact = " ".join(value.split())
    if len(compact) <= max_length:
        return compact
    return compact[: max_length - 1].rstrip() + "."


def _check_id(entry: CweEntry) -> str:
    return entry.id.lower()


def _taxonomy_metadata(cwe_database: CweDatabase) -> dict[str, object] | None:
    metadata = cwe_database.metadata
    return metadata.to_dict() if metadata is not None else None
