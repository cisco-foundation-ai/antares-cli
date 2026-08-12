# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Sweep screen with worker overview and detail views."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.timer import Timer

from antares_cli.core.service import WorkflowResult
from antares_cli.output.finding import Finding, ReportSummary
from antares_cli.tui.screens.help_overlay import HelpOverlay
from antares_cli.tui.screens.save_dialog import SaveDialog
from antares_cli.tui.widgets.activity import ActivityPanel
from antares_cli.tui.widgets.findings import FindingsPanel
from antares_cli.tui.widgets.footer import FooterBar
from antares_cli.tui.widgets.header import HeaderBar
from antares_cli.tui.widgets.worker_list import WorkerList, WorkerStatus


class SweepOverviewScreen(Screen[None]):
    """Top-level sweep view: worker list + aggregated findings."""

    DEFAULT_CSS = """
    SweepOverviewScreen {
        layout: vertical;
    }

    #sweep-body {
        height: 1fr;
    }

    #sweep-workers {
        width: 55%;
    }

    #sweep-findings {
        height: 1fr;
    }

    #sweep-right {
        width: 45%;
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit_app", "Quit"),
        ("escape", "quit_app", "Quit"),
        ("s", "save_report", "Save report"),
        ("question_mark", "show_help", "Help"),
    ]

    def __init__(
        self,
        profile: str = "",
        target: str = "",
        sweep_label: str = "",
        worker_count: int = 0,
        on_drill_in: Callable[[WorkerDetailScreen], None] | None = None,
    ) -> None:
        super().__init__()
        self._profile = profile
        self._target = target
        self._sweep_label = sweep_label
        self._worker_count = worker_count
        self._on_drill_in = on_drill_in
        self._sweep_complete = False
        self._summary: ReportSummary | None = None
        self._per_cwe_results: list[dict[str, Any]] = []
        self._workflow_result: WorkflowResult | None = None

    def compose(self) -> ComposeResult:
        yield HeaderBar(
            mode="sweep",
            profile=self._profile,
            target=self._target,
            extra=f"{self._sweep_label} · {self._worker_count} workers",
        )
        with Horizontal(id="sweep-body"):
            yield WorkerList(id="sweep-workers")
            with Vertical(id="sweep-right"):
                yield FindingsPanel(id="sweep-findings")
        yield FooterBar()

    def on_mount(self) -> None:
        self.footer_bar.update_progress(
            keybinds="↑↓ select  ·  Enter drill in  ·  q quit",
        )
        self.query_one(WorkerList).focus()

    @property
    def worker_list(self) -> WorkerList:
        return self.query_one("#sweep-workers", WorkerList)

    @property
    def findings(self) -> FindingsPanel:
        return self.query_one("#sweep-findings", FindingsPanel)

    @property
    def footer_bar(self) -> FooterBar:
        return self.query_one(FooterBar)

    def on_worker_list_worker_selected(self, event: WorkerList.WorkerSelected) -> None:
        self._open_detail_for_worker(event.worker_id)

    def _on_detail_dismissed(self, navigate_to: int | None) -> None:
        if navigate_to is not None:
            self._open_detail_for_worker(navigate_to)

    def _open_detail_for_worker(self, worker_id: int) -> None:
        info = self.worker_list.get_worker_info(worker_id)
        if info is None:
            return
        label, status = info
        worker_done = status in (WorkerStatus.DONE, WorkerStatus.FAILED)

        detail_screen = WorkerDetailScreen(
            worker_id=worker_id,
            worker_label=label,
            on_drill_in=self._on_drill_in,
            worker_done=worker_done,
            total_workers=self.worker_list.worker_count,
        )
        self.app.push_screen(detail_screen, callback=self._on_detail_dismissed)

    def push_finding(
        self,
        finding: Finding,
        *,
        focus_cwe_ids: list[str] | None = None,
    ) -> None:
        self.findings.push_finding(finding, focus_cwe_ids=focus_cwe_ids)
        self.footer_bar.update_progress(finding_count=self.findings.count)

    def mark_sweep_complete(
        self,
        result: WorkflowResult,
    ) -> None:
        self._sweep_complete = True
        self._workflow_result = result
        self._summary = result.summary
        self._per_cwe_results = list(result.per_cwe_results)
        self.footer_bar.update_progress(
            keybinds="↑↓ select  ·  Enter drill in  ·  s save  ·  q quit",
        )

    def action_save_report(self) -> None:
        if not self._sweep_complete:
            return
        if self._workflow_result is None:
            return
        self.app.push_screen(
            SaveDialog(self._workflow_result),
            callback=self._on_save_done,
        )

    def _on_save_done(self, result: str | None) -> None:
        if result:
            self.footer_bar.update_progress(keybinds=f"saved → {result}  ·  q quit")

    def action_show_help(self) -> None:
        self.app.push_screen(HelpOverlay(mode="sweep-overview"))

    def action_quit_app(self) -> None:
        self.app.exit()


class WorkerDetailScreen(Screen[int | None]):
    """Drill-in view for a single sweep worker."""

    DEFAULT_CSS = """
    WorkerDetailScreen {
        layout: vertical;
    }

    #worker-detail-body {
        height: 1fr;
    }

    #worker-detail-activity {
        width: 1fr;
    }

    #worker-detail-findings {
        width: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back to overview"),
        ("left", "prev_worker", "Previous worker"),
        ("right", "next_worker", "Next worker"),
        ("q", "quit_app", "Quit"),
        ("question_mark", "show_help", "Help"),
    ]

    def __init__(
        self,
        worker_id: int = 0,
        worker_label: str = "",
        on_drill_in: Callable[[WorkerDetailScreen], None] | None = None,
        worker_start_time: float | None = None,
        worker_done: bool = False,
        total_workers: int = 0,
    ) -> None:
        super().__init__()
        self._worker_id = worker_id
        self._worker_label = worker_label
        self._on_drill_in = on_drill_in
        self._worker_start_time = worker_start_time or time.perf_counter()
        self._detail_active = not worker_done
        self._total_workers = total_workers
        self._elapsed_timer: Timer | None = None
        self._blink_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield HeaderBar(
            mode="sweep",
            profile=f"worker {self._worker_id}",
            target=self._worker_label,
        )
        with Horizontal(id="worker-detail-body"):
            yield ActivityPanel(id="worker-detail-activity")
            yield FindingsPanel(id="worker-detail-findings")
        yield FooterBar()

    def on_mount(self) -> None:
        self.footer_bar.update_progress(
            keybinds="Esc back  ·  ←→ prev/next  ·  q quit",
        )
        if self._detail_active and not self.app.is_headless:
            self._elapsed_timer = self.set_interval(0.1, self._tick_elapsed)
            self._blink_timer = self.set_interval(0.5, self._tick_blink)
        if not self._detail_active:
            self.activity.set_cursor_visible(False)
        if self._on_drill_in is not None:
            self.call_after_refresh(self._on_drill_in, self)

    def _tick_elapsed(self) -> None:
        if self._detail_active:
            elapsed = time.perf_counter() - self._worker_start_time
            self.footer_bar.update_progress(elapsed_seconds=elapsed)

    def _tick_blink(self) -> None:
        if self._detail_active:
            self.activity.toggle_cursor()

    def mark_complete(self, summary: str = "") -> None:
        self._stop_activity_timers()
        elapsed = time.perf_counter() - self._worker_start_time
        count = self.findings.count
        done_text = summary or f"{count} finding{'s' if count != 1 else ''} · {elapsed:.1f}s"
        self.activity.push_done(done_text)

    def mark_failed(self, error_message: str) -> None:
        self._stop_activity_timers()
        self.activity.push_result(f"ERROR: {error_message}")
        self.footer_bar.update_progress(keybinds="worker failed  ·  Esc back  ·  q quit")

    def _stop_activity_timers(self) -> None:
        self._detail_active = False
        if self._elapsed_timer is not None:
            self._elapsed_timer.stop()
        if self._blink_timer is not None:
            self._blink_timer.stop()
        self.activity.set_cursor_visible(False)

    @property
    def activity(self) -> ActivityPanel:
        return self.query_one("#worker-detail-activity", ActivityPanel)

    @property
    def findings(self) -> FindingsPanel:
        return self.query_one("#worker-detail-findings", FindingsPanel)

    @property
    def footer_bar(self) -> FooterBar:
        return self.query_one(FooterBar)

    def push_finding(
        self,
        finding: Finding,
        *,
        focus_cwe_ids: list[str] | None = None,
    ) -> None:
        self.findings.push_finding(finding, focus_cwe_ids=focus_cwe_ids)
        self.footer_bar.update_progress(finding_count=self.findings.count)

    def action_go_back(self) -> None:
        self.dismiss(None)

    def action_prev_worker(self) -> None:
        if self._worker_id > 0:
            self.dismiss(self._worker_id - 1)

    def action_next_worker(self) -> None:
        if self._worker_id < self._total_workers - 1:
            self.dismiss(self._worker_id + 1)

    def action_show_help(self) -> None:
        self.app.push_screen(HelpOverlay(mode="worker-detail"))

    def action_quit_app(self) -> None:
        self.app.exit()
