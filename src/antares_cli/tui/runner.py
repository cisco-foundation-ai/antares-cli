# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bridge between synchronous agent loop and async Textual app."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from threading import Thread

from antares_cli.agent.subagent import WorkerResult
from antares_cli.core.service import SweepProgressCallback, SweepProgressEvent, WorkflowResult
from antares_cli.output.finding import Finding, TrajectoryEntry
from antares_cli.output.renderer import AgentStateSnapshot
from antares_cli.tui.app import AntaresApp
from antares_cli.tui.screens.sweep import SweepOverviewScreen, WorkerDetailScreen
from antares_cli.tui.sweep_state import SweepWorkerStore
from antares_cli.tui.widgets.worker_list import WorkerStatus


class SweepRunner:
    """Runs a workflow-service sweep, posting backend events to the TUI."""

    def __init__(
        self,
        app: AntaresApp,
        run_sweep: Callable[[SweepProgressCallback], WorkflowResult],
        target_path: Path,
        worker_labels: list[str],
    ) -> None:
        self._app = app
        self._run_sweep = run_sweep
        self._target_path = target_path
        self._worker_labels = worker_labels
        self._result: WorkflowResult | None = None
        self._error: Exception | None = None
        self._started_at = time.perf_counter()
        self._worker_store = SweepWorkerStore(
            started_at=self._started_at,
        )

    @property
    def result(self) -> WorkflowResult | None:
        return self._result

    @property
    def error(self) -> Exception | None:
        return self._error

    def _get_overview_screen(self) -> SweepOverviewScreen | None:
        for screen in self._app.screen_stack:
            if isinstance(screen, SweepOverviewScreen):
                return screen
        return None

    def start(self) -> None:
        thread = Thread(target=self._run, daemon=True)
        thread.start()

    def _run(self) -> None:
        try:
            self._result = self._run_sweep(self._on_sweep_event)
        except Exception as error:
            self._error = error
            self._app.call_from_thread(self._on_error, str(error))
            return
        self._app.call_from_thread(self._on_complete)

    def _on_sweep_event(self, event: SweepProgressEvent) -> None:
        self._app.call_from_thread(self._apply_sweep_event, event)

    def _apply_sweep_event(self, event: SweepProgressEvent) -> None:
        worker_id = event.worker.worker_index
        self._worker_store.set_focus_cwe_ids(worker_id, event.worker.focus_cwe_ids)
        if event.event_type == "started":
            self._mark_worker_running(worker_id)
        elif event.event_type == "progress" and event.state is not None:
            self._apply_worker_update(worker_id, event.state, event.finding)
        elif event.event_type == "completed" and event.result is not None:
            self._mark_worker_done(worker_id, event.result)
        elif event.event_type == "failed":
            self._mark_worker_failed(worker_id, event.result, event.error_message)

    def _apply_worker_update(
        self,
        worker_id: int,
        state: AgentStateSnapshot,
        finding: Finding | None,
    ) -> None:
        new_entries, accepted_finding = self._worker_store.record_progress(
            worker_id, state, finding
        )
        active_screen = self._app.screen
        self._update_active_worker_detail(worker_id, active_screen, new_entries, accepted_finding)
        self._update_worker_overview(worker_id, new_entries, accepted_finding)
        if hasattr(active_screen, "footer_bar"):
            elapsed = time.perf_counter() - self._started_at
            active_screen.footer_bar.update_progress(elapsed_seconds=elapsed)

    def _update_active_worker_detail(
        self,
        worker_id: int,
        active_screen: object,
        new_entries: list[TrajectoryEntry],
        finding: Finding | None,
    ) -> None:
        if not _is_detail_screen_for_worker(active_screen, worker_id):
            return
        if not isinstance(active_screen, WorkerDetailScreen):
            return
        self._ensure_detail_roots(active_screen)
        _append_detail_entries(active_screen, new_entries)
        if finding is not None:
            active_screen.push_finding(
                finding,
                focus_cwe_ids=self._worker_store.focus_cwe_ids(worker_id),
            )

    def _update_worker_overview(
        self,
        worker_id: int,
        new_entries: list[TrajectoryEntry],
        finding: Finding | None,
    ) -> None:
        overview = self._get_overview_screen()
        if overview is None:
            return
        overview.worker_list.update_worker(
            worker_id,
            tool_call_count=self._worker_store.tool_call_count(worker_id),
            elapsed_seconds=self._worker_store.elapsed(worker_id),
            last_tool_call=_last_tool_call(new_entries),
        )
        if finding is not None:
            self._push_overview_finding(overview, worker_id, finding)

    def _push_overview_finding(
        self,
        overview: SweepOverviewScreen,
        worker_id: int,
        finding: Finding,
    ) -> None:
        overview.worker_list.update_worker(
            worker_id,
            finding_count=len(self._worker_store.findings(worker_id)),
        )
        overview.push_finding(
            finding,
            focus_cwe_ids=self._worker_store.focus_cwe_ids(worker_id),
        )
        self._worker_store.increment_pushed_count(worker_id)

    def _ensure_detail_roots(self, active_screen: WorkerDetailScreen) -> None:
        if active_screen.activity._workspace_root:
            return
        active_screen.activity.set_workspace_root(str(self._target_path))
        active_screen.findings.set_workspace_root(str(self._target_path))

    def _mark_worker_running(self, worker_id: int) -> None:
        self._worker_store.mark_started(worker_id)
        overview = self._get_overview_screen()
        if overview is not None:
            if not overview.findings._workspace_root:
                overview.findings.set_workspace_root(str(self._target_path))
            overview.worker_list.update_worker(worker_id, status=WorkerStatus.RUNNING)
            elapsed = time.perf_counter() - self._started_at
            overview.footer_bar.update_progress(
                files_total=len(self._worker_labels),
                elapsed_seconds=elapsed,
            )

    def _mark_worker_done(self, worker_id: int, result: WorkerResult) -> None:
        self._worker_store.mark_completed(worker_id, result)

        active_screen = self._app.screen
        if isinstance(active_screen, WorkerDetailScreen) and active_screen._worker_id == worker_id:
            active_screen.mark_complete()

        overview = self._get_overview_screen()
        if overview is not None:
            display_findings = self._worker_store.findings(worker_id)
            overview.worker_list.update_worker(
                worker_id,
                status=WorkerStatus.DONE,
                finding_count=len(display_findings),
                tool_call_count=result.tool_call_count,
                elapsed_seconds=self._worker_store.elapsed(worker_id),
            )
            already_pushed = self._worker_store.pushed_count(worker_id)
            for finding in display_findings[already_pushed:]:
                overview.push_finding(
                    finding,
                    focus_cwe_ids=self._worker_store.focus_cwe_ids(worker_id),
                )
            self._worker_store.set_pushed_count(worker_id, len(display_findings))

            overview.footer_bar.update_progress(
                files_done=self._worker_store.completed_count,
                finding_count=self._worker_store.total_finding_count,
            )

    def _mark_worker_failed(
        self,
        worker_id: int,
        result: WorkerResult | None,
        error_message: str | None,
    ) -> None:
        if result is not None:
            self._worker_store.mark_completed(worker_id, result)
        message = error_message or "Worker failed before completing its scan."
        active_screen = self._app.screen
        if _is_detail_screen_for_worker(active_screen, worker_id) and isinstance(
            active_screen, WorkerDetailScreen
        ):
            active_screen.mark_failed(message)
        overview = self._get_overview_screen()
        if overview is not None:
            overview.worker_list.update_worker(
                worker_id,
                status=WorkerStatus.FAILED,
                tool_call_count=result.tool_call_count if result is not None else None,
                elapsed_seconds=self._worker_store.elapsed(worker_id),
            )
            overview.footer_bar.update_progress(
                files_done=self._worker_store.completed_count,
            )

    def _on_error(self, error_message: str) -> None:
        active_screen = self._app.screen
        if isinstance(active_screen, WorkerDetailScreen):
            active_screen.mark_failed(error_message)
        overview = self._get_overview_screen()
        if overview is None:
            return
        for worker_id in range(len(self._worker_labels)):
            overview.worker_list.update_worker(worker_id, status=WorkerStatus.FAILED)
        overview.footer_bar.update_progress(
            keybinds=f"error: {error_message}  ·  q quit",
        )

    def replay_into_detail_screen(self, screen: WorkerDetailScreen) -> None:
        worker_id = screen._worker_id
        worker_start_time = self._worker_store.start_time(worker_id)
        if worker_start_time is not None:
            screen._worker_start_time = worker_start_time
        screen.activity.set_workspace_root(str(self._target_path))
        screen.findings.set_workspace_root(str(self._target_path))
        _append_detail_entries(screen, self._worker_store.trajectories(worker_id))
        for finding in self._worker_store.findings(worker_id):
            screen.push_finding(
                finding,
                focus_cwe_ids=self._worker_store.focus_cwe_ids(worker_id),
            )
        result = self._worker_store.result(worker_id)
        if result is not None and result.error_message is not None:
            screen.mark_failed(result.error_message)
            return
        if not screen._detail_active:
            findings_count = len(self._worker_store.findings(worker_id))
            screen.activity.push_done(
                f"{findings_count} finding{'s' if findings_count != 1 else ''}"
            )

    def _on_complete(self) -> None:
        overview = self._get_overview_screen()
        if overview is not None:
            elapsed = time.perf_counter() - self._started_at
            overview.footer_bar.update_progress(
                files_done=len(self._worker_labels),
                files_total=len(self._worker_labels),
                elapsed_seconds=elapsed,
            )
            if self._result is not None:
                overview.mark_sweep_complete(self._result)


def _is_detail_screen_for_worker(active_screen: object, worker_id: int) -> bool:
    return isinstance(active_screen, WorkerDetailScreen) and active_screen._worker_id == worker_id


def _append_detail_entries(screen: WorkerDetailScreen, entries: list[TrajectoryEntry]) -> None:
    for entry in entries:
        if entry.entry_type == "tool_call":
            screen.activity.push_command(entry.content)
        elif entry.entry_type == "tool_response":
            screen.activity.push_result(entry.content)
        elif entry.entry_type == "think":
            screen.activity.push_thinking(entry.content)


def _last_tool_call(entries: list[TrajectoryEntry]) -> str:
    for entry in reversed(entries):
        if entry.entry_type == "tool_call":
            return entry.content
    return ""
