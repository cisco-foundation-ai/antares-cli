# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""CWE-first Antares workflow service."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from antares_cli.agent.contracts import ProgressCallback
from antares_cli.agent.execution_policy import (
    DEFAULT_TERMINAL_CALL_BUDGET,
    resolve_terminal_call_budget,
)
from antares_cli.agent.subagent import (
    MergedSweepResult,
    SweepOrchestrator,
    WorkerResult,
    WorkerTask,
)
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.config import AntaresSettings
from antares_cli.core.cwe import normalize_cwe_ids
from antares_cli.core.cwe_selection import CweSelectionRequest, CweSelectionService
from antares_cli.core.cwe_selection_limits import DEFAULT_AUTOMATIC_CWE_LIMIT
from antares_cli.core.cwe_selection_models import CweAbstractionLevel, CweSelectionPlan, ScanScope
from antares_cli.core.runtime import RuntimeContext, RuntimeFactory, RuntimeOptions
from antares_cli.core.sensitive_paths import resolve_allowed_sensitive_files
from antares_cli.core.worker_limits import DEFAULT_SWEEP_WORKERS, resolve_sweep_worker_count
from antares_cli.core.workflow_metadata import (
    model_configuration_metadata,
    per_cwe_results,
    workflow_metadata,
)
from antares_cli.knowledge.cwe_database import CweDatabase, CweEntry
from antares_cli.output.finding import Finding, ReportSummary, deduplicate_findings
from antares_cli.output.renderer import AgentStateSnapshot
from antares_cli.output.report import public_per_cwe_results
from antares_cli.tools.readonly_workspace import ReadOnlyRepositorySnapshot


@dataclass(slots=True)
class QueryRequest:
    target: Path
    query: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    profile: str | None = None
    model: str | None = None
    backend: str | None = None
    endpoint: str | None = None
    api_key: str | None = None
    terminal_call_budget: int | None = DEFAULT_TERMINAL_CALL_BUDGET
    additional_ignore_paths: list[str] = field(default_factory=list)
    allow_sensitive_files: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SweepRequest:
    target: Path
    cwe_ids: list[str] = field(default_factory=list)
    query: str | None = None
    workers: int = DEFAULT_SWEEP_WORKERS
    profile: str | None = None
    model: str | None = None
    backend: str | None = None
    endpoint: str | None = None
    api_key: str | None = None
    scope: ScanScope = "auto"
    cwe_level: CweAbstractionLevel = "all"
    max_cwes: int = DEFAULT_AUTOMATIC_CWE_LIMIT
    terminal_call_budget: int | None = DEFAULT_TERMINAL_CALL_BUDGET
    additional_ignore_paths: list[str] = field(default_factory=list)
    allow_sensitive_files: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class SweepTaskDescriptor:
    worker_index: int
    label: str
    focus_cwe_ids: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class SweepPreview:
    selection_plan: CweSelectionPlan
    workers: tuple[SweepTaskDescriptor, ...]


@dataclass(slots=True)
class SweepProgressEvent:
    event_type: Literal["started", "progress", "completed", "failed"]
    worker: SweepTaskDescriptor
    state: AgentStateSnapshot | None = None
    finding: Finding | None = None
    result: WorkerResult | None = None
    error_message: str | None = None


SweepProgressCallback = Callable[[SweepProgressEvent], None]


@dataclass(slots=True)
class WorkflowResult:
    findings: list[Finding]
    summary: ReportSummary
    metadata: dict[str, Any]
    per_cwe_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "summary": self.summary.to_public_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }
        if self.per_cwe_results:
            payload["per_cwe_results"] = public_per_cwe_results(self.per_cwe_results)
        warnings = self._collect_warnings()
        if warnings:
            payload["warnings"] = warnings
        return payload

    def _collect_warnings(self) -> list[str]:
        warnings: list[str] = []
        if self.summary.generation_errors > 0:
            warnings.append(
                f"Model backend error interrupted the scan "
                f"({self.summary.generation_errors} error(s)); results may be incomplete"
            )
        if self.summary.failed_workers > 0:
            warnings.append(
                f"{self.summary.failed_workers}/{self.summary.total_workers} CWE workers failed; "
                "some vulnerability classes were not scanned"
            )
        if self.summary.incomplete_reason is not None:
            warnings.append(self.summary.incomplete_reason)
        return warnings

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class SecurityWorkflowService:
    """Application service shared by the CLI and interactive TUI."""

    def __init__(self, runtime_factory: RuntimeFactory | None = None) -> None:
        self._runtime_factory = runtime_factory or RuntimeFactory()

    def run_query(
        self,
        request: QueryRequest,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> WorkflowResult:
        effective_budget = resolve_terminal_call_budget(request.terminal_call_budget)
        request.cwe_ids = normalize_cwe_ids(
            request.cwe_ids,
            self._load_cwe_database(),
        )
        request.allow_sensitive_files = list(
            resolve_allowed_sensitive_files(request.target, request.allow_sensitive_files)
        )
        runtime = self._runtime_factory.build(_runtime_options_from_query(request))
        try:
            return self._run_query_with_runtime(
                request,
                runtime=runtime,
                effective_budget=effective_budget,
                progress_callback=progress_callback,
            )
        finally:
            _close_runtime_backend(runtime)

    @staticmethod
    def _run_query_with_runtime(
        request: QueryRequest,
        *,
        runtime: RuntimeContext,
        effective_budget: int,
        progress_callback: ProgressCallback | None,
    ) -> WorkflowResult:
        cwe_ids = normalize_cwe_ids(request.cwe_ids, runtime.cwe_database)
        allowed_sensitive_files = resolve_allowed_sensitive_files(
            request.target,
            request.allow_sensitive_files,
        )

        with ReadOnlyRepositorySnapshot(
            request.target,
            ignore_paths=_effective_ignore_paths(
                runtime.settings.ignore_paths,
                request.additional_ignore_paths,
            ),
            allow_sensitive_files=allowed_sensitive_files,
        ) as snapshot:
            agent_loop = runtime.create_agent_loop(request.target, snapshot=snapshot)
            agent_result = agent_loop.run_audit(
                request.target,
                user_query=_cwe_analysis_prompt(
                    cwe_ids,
                    cwe_database=runtime.cwe_database,
                    query=request.query,
                ),
                focus_cwe_ids=cwe_ids or None,
                progress_callback=progress_callback,
                terminal_call_budget=effective_budget,
            )

        metadata = workflow_metadata(
            target=request.target,
            query=request.query,
            cwe_ids=cwe_ids,
            model=runtime.settings.model,
            backend=runtime.settings.backend,
            profile=request.profile,
            terminal_call_budget=effective_budget,
            allowed_sensitive_files=allowed_sensitive_files,
        )
        metadata["model_configuration"] = model_configuration_metadata(runtime)
        metadata["cwe_ids"] = cwe_ids

        findings = _deterministic_findings(agent_result.findings)
        summary = _summary_for_findings(findings, agent_result.summary)
        return WorkflowResult(findings=findings, summary=summary, metadata=metadata)

    def preview_sweep_details(self, request: SweepRequest) -> SweepPreview:
        """Return selection rationale and worker layout without model inference."""
        resolve_sweep_worker_count(request.workers)
        cwe_database = self._load_cwe_database()
        settings = AntaresSettings.load(start_path=request.target)
        allowed_sensitive_files = resolve_allowed_sensitive_files(
            request.target,
            request.allow_sensitive_files,
        )
        selection_plan = _sweep_selection_plan(
            request,
            cwe_database=cwe_database,
            ignore_paths=_effective_ignore_paths(
                settings.ignore_paths,
                request.additional_ignore_paths,
            ),
            allow_sensitive_files=allowed_sensitive_files,
        )
        tasks = _cwe_tasks(
            selection_plan.cwe_ids(),
            cwe_database=cwe_database,
            model_label="preview",
            query=request.query,
        )
        return SweepPreview(
            selection_plan=selection_plan,
            workers=tuple(_task_descriptors(tasks, cwe_database=cwe_database)),
        )

    def run_cwe_sweep(
        self,
        request: SweepRequest,
        *,
        progress_callback: SweepProgressCallback | None = None,
        selection_plan: CweSelectionPlan | None = None,
    ) -> WorkflowResult:
        worker_count = resolve_sweep_worker_count(request.workers)
        effective_budget = resolve_terminal_call_budget(request.terminal_call_budget)
        if request.cwe_ids:
            request.cwe_ids = normalize_cwe_ids(
                request.cwe_ids,
                self._load_cwe_database(),
            )
        request.allow_sensitive_files = list(
            resolve_allowed_sensitive_files(request.target, request.allow_sensitive_files)
        )
        runtime = self._runtime_factory.build(_runtime_options_from_sweep(request))
        try:
            return self._run_cwe_sweep_with_runtime(
                request,
                runtime=runtime,
                worker_count=worker_count,
                effective_budget=effective_budget,
                progress_callback=progress_callback,
                selection_plan=selection_plan,
            )
        finally:
            _close_runtime_backend(runtime)

    def _load_cwe_database(self) -> CweDatabase:
        loader = getattr(self._runtime_factory, "load_cwe_database", None)
        if callable(loader):
            database = loader()
            if not isinstance(database, CweDatabase):
                raise TypeError("Runtime factory returned an invalid CWE database")
            return database
        return CweDatabase.load_default()

    @staticmethod
    def _run_cwe_sweep_with_runtime(
        request: SweepRequest,
        *,
        runtime: RuntimeContext,
        worker_count: int,
        effective_budget: int,
        progress_callback: SweepProgressCallback | None,
        selection_plan: CweSelectionPlan | None,
    ) -> WorkflowResult:
        allowed_sensitive_files = resolve_allowed_sensitive_files(
            request.target,
            request.allow_sensitive_files,
        )
        selection_plan = selection_plan or _sweep_selection_plan(
            request,
            cwe_database=runtime.cwe_database,
            ignore_paths=_effective_ignore_paths(
                runtime.settings.ignore_paths,
                request.additional_ignore_paths,
            ),
            allow_sensitive_files=allowed_sensitive_files,
        )
        cwe_ids = selection_plan.cwe_ids()

        tasks = _cwe_tasks(
            cwe_ids,
            cwe_database=runtime.cwe_database,
            model_label=runtime.model_label,
            query=request.query,
            terminal_call_budget=effective_budget,
        )

        with ReadOnlyRepositorySnapshot(
            request.target,
            ignore_paths=_effective_ignore_paths(
                runtime.settings.ignore_paths,
                request.additional_ignore_paths,
            ),
            allow_sensitive_files=allowed_sensitive_files,
        ) as snapshot:
            merged_result, duration_seconds = _run_worker_tasks(
                runtime,
                request,
                tasks,
                worker_count=worker_count,
                snapshot=snapshot,
                progress_callback=progress_callback,
            )
        findings = _deterministic_findings(merged_result.all_findings)
        summary = _summary_for_merged_result(findings, merged_result, duration_seconds)
        metadata = workflow_metadata(
            target=request.target,
            query=request.query,
            cwe_ids=cwe_ids,
            model=runtime.settings.model,
            backend=runtime.settings.backend,
            profile=request.profile,
            mode="cwe_sweep",
            terminal_call_budget=effective_budget,
            allowed_sensitive_files=allowed_sensitive_files,
        )
        metadata["model_configuration"] = model_configuration_metadata(runtime)
        metadata["selection"] = selection_plan.to_dict()
        return WorkflowResult(
            findings=findings,
            summary=summary,
            metadata=metadata,
            per_cwe_results=per_cwe_results(merged_result.worker_results, cwe_ids),
        )


def _close_runtime_backend(runtime: RuntimeContext) -> None:
    backend = runtime.inference_backend
    close = getattr(backend, "close", None)
    if callable(close):
        close()


def _effective_ignore_paths(
    configured_paths: list[str] | tuple[str, ...],
    additional_paths: list[str] | tuple[str, ...],
) -> list[str]:
    return list(dict.fromkeys([*configured_paths, *additional_paths]))


def _sweep_selection_plan(
    request: SweepRequest,
    *,
    cwe_database: CweDatabase,
    ignore_paths: list[str] | tuple[str, ...],
    allow_sensitive_files: tuple[str, ...] = (),
) -> CweSelectionPlan:
    return CweSelectionService(cwe_database=cwe_database).select(
        CweSelectionRequest(
            target=request.target,
            cwe_ids=request.cwe_ids,
            ignore_paths=tuple(ignore_paths),
            allow_sensitive_files=allow_sensitive_files,
            scope=request.scope,
            cwe_level=request.cwe_level,
            max_cwes=request.max_cwes,
        )
    )


def _runtime_options_from_query(request: QueryRequest) -> RuntimeOptions:
    return RuntimeOptions(
        target=request.target,
        profile=request.profile,
        model=request.model,
        backend=request.backend,
        endpoint=request.endpoint,
        api_key=request.api_key,
    )


def _runtime_options_from_sweep(request: SweepRequest) -> RuntimeOptions:
    return RuntimeOptions(
        target=request.target,
        profile=request.profile,
        model=request.model,
        backend=request.backend,
        endpoint=request.endpoint,
        api_key=request.api_key,
    )


def _cwe_tasks(
    cwe_ids: list[str],
    *,
    cwe_database: CweDatabase,
    model_label: str,
    query: str | None,
    terminal_call_budget: int | None = None,
) -> list[WorkerTask]:
    return [
        WorkerTask(
            description=_cwe_analysis_prompt(
                [cwe_id],
                cwe_database=cwe_database,
                query=query,
            )
            or cwe_id,
            focus_cwe_ids=[cwe_id],
            model_profile=model_label,
            task_id=cwe_id.replace("CWE-", "cwe-"),
            terminal_call_budget=terminal_call_budget,
        )
        for cwe_id in cwe_ids
    ]


def _task_descriptors(
    tasks: list[WorkerTask],
    *,
    cwe_database: CweDatabase | None = None,
) -> list[SweepTaskDescriptor]:
    return [
        SweepTaskDescriptor(
            worker_index=index,
            label=_task_label(task, index, cwe_database=cwe_database),
            focus_cwe_ids=list(task.focus_cwe_ids),
        )
        for index, task in enumerate(tasks)
    ]


def _task_label(
    task: WorkerTask,
    index: int,
    *,
    cwe_database: CweDatabase | None,
) -> str:
    if task.focus_cwe_ids:
        return ", ".join(
            _cwe_display_label(cwe_id, cwe_database=cwe_database) for cwe_id in task.focus_cwe_ids
        )
    return task.description or f"Task {index + 1}"


def _cwe_display_label(cwe_id: str, *, cwe_database: CweDatabase | None) -> str:
    if cwe_database is None:
        return cwe_id
    entry = cwe_database.get_by_id(cwe_id)
    if entry is None or _is_placeholder_cwe_entry(entry):
        return cwe_id
    return f"{cwe_id} · {entry.name}"


def _run_worker_tasks(
    runtime: RuntimeContext,
    request: SweepRequest,
    tasks: list[WorkerTask],
    *,
    worker_count: int,
    snapshot: ReadOnlyRepositorySnapshot,
    progress_callback: SweepProgressCallback | None = None,
) -> tuple[MergedSweepResult, float]:
    started_at = time.perf_counter()
    descriptors_by_task_id = {
        task.task_id: descriptor
        for task, descriptor in zip(
            tasks,
            _task_descriptors(tasks, cwe_database=runtime.cwe_database),
            strict=True,
        )
    }

    def emit_event(event: SweepProgressEvent) -> None:
        if progress_callback is not None:
            progress_callback(event)

    def on_worker_started(worker_index: int, task: WorkerTask) -> None:
        emit_event(
            SweepProgressEvent(
                event_type="started",
                worker=descriptors_by_task_id[task.task_id],
            )
        )

    def on_worker_progress(
        worker_index: int,
        task: WorkerTask,
        state: AgentStateSnapshot,
        finding: Finding | None,
    ) -> None:
        emit_event(
            SweepProgressEvent(
                event_type="progress",
                worker=descriptors_by_task_id[task.task_id],
                state=state,
                finding=finding,
            )
        )

    def on_worker_result(worker_result: WorkerResult) -> None:
        descriptor = descriptors_by_task_id.get(worker_result.task_id)
        if descriptor is None:
            return
        emit_event(
            SweepProgressEvent(
                event_type="failed" if worker_result.error_message else "completed",
                worker=descriptor,
                result=worker_result,
                error_message=worker_result.error_message,
            )
        )

    if runtime.inference_backend is None:
        raise RuntimeError("Sweep runtime did not provide an inference backend")
    orchestrator = SweepOrchestrator(
        worker_count=worker_count,
        inference_backend=runtime.inference_backend,
        tool_router_factory=lambda workspace_root: ToolRouter(
            workspace_root,
            snapshot=snapshot,
        ),
        cwe_database=runtime.cwe_database,
        model_adapter=runtime.model_adapter,
    )
    merged_result = orchestrator.run_orchestrated_sweep(
        request.target,
        tasks,
        progress_callback=on_worker_result,
        worker_start_callback=on_worker_started,
        worker_progress_callback=on_worker_progress,
    )
    return merged_result, time.perf_counter() - started_at


def _cwe_analysis_prompt(
    cwe_ids: list[str],
    *,
    cwe_database: CweDatabase,
    query: str | None,
) -> str | None:
    if not cwe_ids:
        return query

    label = "vulnerability class" if len(cwe_ids) == 1 else "vulnerability classes"
    context_blocks = [_cwe_context_block(cwe_id, cwe_database=cwe_database) for cwe_id in cwe_ids]
    context_text = "\n\n".join(context_blocks)

    closing = (
        "Use the terminal tool to explore and determine if this vulnerability exists. "
        "Then either submit the vulnerable file(s) or declare no vulnerability found."
    )

    base = f"Analyze this codebase for the following {label}:\n\n{context_text}\n\n{closing}"
    if query:
        return f"{base}\n\nAdditional instructions:\n{query}"
    return base


def _cwe_context_block(cwe_id: str, *, cwe_database: CweDatabase) -> str:
    entry = cwe_database.get_by_id(cwe_id)
    if entry is None or _is_placeholder_cwe_entry(entry):
        return cwe_id

    description = entry.description.strip()
    header = f"{entry.id}: {entry.name}"

    parts = [header]
    if entry.likelihood_of_exploit:
        parts.append(f"Likelihood of Exploit: {entry.likelihood_of_exploit}")
    parts.append(description)
    extended_description = entry.extended_description.strip()
    if extended_description and extended_description != description:
        parts.append(extended_description)
    return "\n".join(parts)


def _is_placeholder_cwe_entry(entry: CweEntry) -> bool:
    return entry.name.startswith("Placeholder CWE") or entry.description.startswith(
        "Offline placeholder entry"
    )


def _deterministic_findings(findings: list[Finding]) -> list[Finding]:
    return deduplicate_findings(findings)


def _summary_for_findings(findings: list[Finding], source_summary: ReportSummary) -> ReportSummary:
    return ReportSummary(
        total_findings=len(findings),
        tool_call_count=source_summary.tool_call_count,
        duration_seconds=source_summary.duration_seconds,
        investigation_trace=source_summary.investigation_trace,
        cwe_ids_triggered=sorted({cwe_id for finding in findings for cwe_id in finding.cwe_ids}),
        failed_tool_calls=source_summary.failed_tool_calls,
        retried_turns=source_summary.retried_turns,
        generation_errors=source_summary.generation_errors,
        incomplete_reason=source_summary.incomplete_reason,
    )


def _summary_for_merged_result(
    findings: list[Finding],
    merged_result: MergedSweepResult,
    duration_seconds: float,
) -> ReportSummary:
    return ReportSummary(
        total_findings=len(findings),
        tool_call_count=merged_result.total_tool_calls,
        duration_seconds=duration_seconds,
        investigation_trace=None,
        cwe_ids_triggered=sorted({cwe_id for finding in findings for cwe_id in finding.cwe_ids}),
        failed_tool_calls=sum(
            worker_result.failed_tool_calls for worker_result in merged_result.worker_results
        ),
        retried_turns=sum(
            worker_result.retried_turns for worker_result in merged_result.worker_results
        ),
        generation_errors=sum(
            worker_result.generation_errors for worker_result in merged_result.worker_results
        ),
        failed_workers=merged_result.failed_task_count,
        total_workers=merged_result.completed_task_count + merged_result.failed_task_count,
    )
