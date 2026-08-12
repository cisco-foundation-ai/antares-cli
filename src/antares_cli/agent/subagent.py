# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Parallel subagent orchestration for sweep mode and primary/worker orchestration."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from antares_cli.agent.model_adapter import ModelAdapter
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.agent.trace import investigation_trace_from_error
from antares_cli.core.worker_limits import resolve_sweep_worker_count
from antares_cli.inference.backend import InferenceBackend, InferenceError
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.output.finding import Finding, finding_sort_key

WorkerStartCallback = Callable[[int, "WorkerTask"], None]
WorkerAgentProgressCallback = Callable[[int, "WorkerTask", Any, Finding | None], None]

# ---------------------------------------------------------------------------
# Primary/Worker orchestration model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WorkerTask:
    description: str
    focus_cwe_ids: list[str] = field(default_factory=list)
    model_profile: str = "350M-dense"
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    terminal_call_budget: int | None = None


@dataclass(slots=True)
class WorkerResult:
    task_id: str
    findings: list[Finding]
    tool_call_count: int
    duration_seconds: float
    investigation_trace: str | None = None
    error_message: str | None = None
    generation_errors: int = 0
    failed_tool_calls: int = 0
    retried_turns: int = 0


@dataclass(slots=True)
class MergedSweepResult:
    all_findings: list[Finding]
    worker_results: list[WorkerResult]
    total_tool_calls: int
    completed_task_count: int
    failed_task_count: int


class SweepOrchestrator:
    def __init__(
        self,
        *,
        worker_count: int,
        inference_backend: InferenceBackend,
        tool_router_factory: Callable[[str], ToolRouter],
        cwe_database: CweDatabase,
        model_adapter: ModelAdapter | None = None,
    ) -> None:
        self.worker_count = resolve_sweep_worker_count(worker_count)
        self.inference_backend = inference_backend
        self.tool_router_factory = tool_router_factory
        self.cwe_database = cwe_database
        self.model_adapter = model_adapter

    def run_orchestrated_sweep(
        self,
        repo_path: Path,
        tasks: list[WorkerTask],
        progress_callback: Callable[[WorkerResult], None] | None = None,
        worker_start_callback: WorkerStartCallback | None = None,
        worker_progress_callback: WorkerAgentProgressCallback | None = None,
    ) -> MergedSweepResult:
        worker_results: list[WorkerResult] = []
        completed_task_count = 0
        failed_task_count = 0

        if not tasks:
            return MergedSweepResult(
                all_findings=[],
                worker_results=[],
                total_tool_calls=0,
                completed_task_count=0,
                failed_task_count=0,
            )

        with ThreadPoolExecutor(max_workers=min(self.worker_count, len(tasks))) as executor:
            future_to_task = {
                executor.submit(
                    self._execute_worker_task,
                    repo_path,
                    task,
                    worker_index,
                    worker_start_callback,
                    worker_progress_callback,
                ): task
                for worker_index, task in enumerate(tasks)
            }
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    worker_result = future.result()
                except InferenceError as error:
                    investigation_trace = investigation_trace_from_error(error)
                    worker_result = WorkerResult(
                        task_id=task.task_id,
                        findings=[],
                        tool_call_count=0,
                        duration_seconds=0.0,
                        investigation_trace=(
                            str(investigation_trace) if investigation_trace is not None else None
                        ),
                        error_message=str(error),
                        generation_errors=1,
                    )
                except Exception as error:
                    investigation_trace = investigation_trace_from_error(error)
                    worker_result = WorkerResult(
                        task_id=task.task_id,
                        findings=[],
                        tool_call_count=0,
                        duration_seconds=0.0,
                        investigation_trace=(
                            str(investigation_trace) if investigation_trace is not None else None
                        ),
                        error_message=f"{type(error).__name__}: {error}",
                    )

                worker_results.append(worker_result)
                if worker_result.error_message is not None:
                    failed_task_count += 1
                else:
                    completed_task_count += 1

                if progress_callback is not None:
                    progress_callback(worker_result)

        merged_findings = self._merge_findings(worker_results)
        total_tool_calls = sum(worker_result.tool_call_count for worker_result in worker_results)
        return MergedSweepResult(
            all_findings=merged_findings,
            worker_results=worker_results,
            total_tool_calls=total_tool_calls,
            completed_task_count=completed_task_count,
            failed_task_count=failed_task_count,
        )

    def _execute_worker_task(
        self,
        repo_path: Path,
        task: WorkerTask,
        worker_index: int = 0,
        worker_start_callback: WorkerStartCallback | None = None,
        worker_progress_callback: WorkerAgentProgressCallback | None = None,
    ) -> WorkerResult:
        from antares_cli.agent.loop import AntaresAgentLoop

        worker_started_at = time.perf_counter()
        if worker_start_callback is not None:
            worker_start_callback(worker_index, task)

        workspace_root = str(repo_path)
        tool_router = self.tool_router_factory(workspace_root)

        agent_loop = AntaresAgentLoop(
            tool_router=tool_router,
            cwe_database=self.cwe_database,
            inference_backend=self.inference_backend,
            model_label=task.model_profile,
            model_adapter=self.model_adapter,
        )

        focus_cwe_ids = task.focus_cwe_ids if task.focus_cwe_ids else None

        audit_result = agent_loop.run_audit(
            repo_path,
            user_query=task.description,
            focus_cwe_ids=focus_cwe_ids,
            progress_callback=(
                None
                if worker_progress_callback is None
                else lambda state, finding: worker_progress_callback(
                    worker_index, task, state, finding
                )
            ),
            terminal_call_budget=task.terminal_call_budget,
        )
        if task.focus_cwe_ids:
            for finding in audit_result.findings:
                if not finding.cwe_ids:
                    finding.cwe_ids = list(task.focus_cwe_ids)

        worker_duration_seconds = time.perf_counter() - worker_started_at
        generation_errors = audit_result.summary.generation_errors
        error_message = None
        if generation_errors > 0:
            error_message = (
                "Model generation error interrupted this worker; results may be incomplete"
            )
        elif audit_result.summary.incomplete_reason is not None:
            error_message = audit_result.summary.incomplete_reason

        return WorkerResult(
            task_id=task.task_id,
            findings=audit_result.findings,
            tool_call_count=audit_result.summary.tool_call_count,
            duration_seconds=worker_duration_seconds,
            investigation_trace=str(audit_result.investigation_trace),
            error_message=error_message,
            generation_errors=generation_errors,
            failed_tool_calls=audit_result.summary.failed_tool_calls,
            retried_turns=audit_result.summary.retried_turns,
        )

    def _merge_findings(self, worker_results: list[WorkerResult]) -> list[Finding]:
        deduplicated_findings: dict[tuple[str, str], Finding] = {}

        for worker_result in worker_results:
            for finding in worker_result.findings:
                dedupe_key = (finding.file_path, finding.title)
                existing_finding = deduplicated_findings.get(dedupe_key)
                if existing_finding is None or finding.confidence > existing_finding.confidence:
                    deduplicated_findings[dedupe_key] = finding

        sorted_findings = sorted(deduplicated_findings.values(), key=finding_sort_key)
        return sorted_findings
