# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Worker list widget — selectable checklist for sweep mode."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Static

from antares_cli.tui.theme import (
    CHROME_DIM,
    WORKER_DONE,
    WORKER_QUEUED,
    WORKER_RUNNING,
)


class WorkerStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(slots=True)
class WorkerState:
    worker_id: int
    label: str
    status: WorkerStatus = WorkerStatus.QUEUED
    finding_count: int = 0
    tool_call_count: int = 0
    elapsed_seconds: float = 0.0
    last_tool_call: str = ""


class WorkerRow(Static):
    """A single worker row inside the scrollable worker list."""

    DEFAULT_CSS = """
    WorkerRow {
        height: auto;
        width: 1fr;
        margin: 0 0 1 0;
    }
    """

    def __init__(self, worker: WorkerState, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.worker = worker
        self.selected = False

    def render(self) -> Text:
        worker = self.worker
        output = Text(overflow="fold")
        self._append_header(output, worker)
        self._append_status_details(output, worker)
        return output

    def _append_header(self, output: Text, worker: WorkerState) -> None:
        output.append(" ▸ " if self.selected else "   ", style="bold")
        marker, style = _status_marker(worker.status)
        output.append(marker, style=style)
        label_style = "bold" if self.selected else "default"
        output.append(worker.label, style=label_style)
        output.append("\n      ", style="default")

    def _append_status_details(self, output: Text, worker: WorkerState) -> None:
        if worker.status == WorkerStatus.QUEUED:
            output.append("waiting", style=CHROME_DIM)
            return
        if worker.status == WorkerStatus.FAILED:
            output.append("failed", style="bold red")
            return
        self._append_active_details(output, worker)

    def _append_active_details(self, output: Text, worker: WorkerState) -> None:
        _append_metric(output, f"{worker.tool_call_count} calls", worker.tool_call_count > 0)
        _append_metric(output, f"{worker.elapsed_seconds:.1f}s", worker.elapsed_seconds > 0)
        self._append_finding_counts(output, worker)
        if worker.status == WorkerStatus.RUNNING and worker.last_tool_call:
            output.append(worker.last_tool_call, style=CHROME_DIM)

    def _append_finding_counts(self, output: Text, worker: WorkerState) -> None:
        if worker.finding_count > 0:
            output.append(str(worker.finding_count), style="bold")
            output.append(_finding_count_label(worker.finding_count), style=CHROME_DIM)
            output.append(" ", style="default")
        elif worker.status == WorkerStatus.DONE:
            output.append("0 findings", style=CHROME_DIM)


def _status_marker(status: WorkerStatus) -> tuple[str, str]:
    if status == WorkerStatus.DONE:
        return "✓ ", WORKER_DONE
    if status == WorkerStatus.RUNNING:
        return "● ", f"bold {WORKER_RUNNING}"
    if status == WorkerStatus.FAILED:
        return "✗ ", "bold red"
    return "○ ", WORKER_QUEUED


def _append_metric(output: Text, label: str, enabled: bool) -> None:
    if not enabled:
        return
    output.append(label, style=CHROME_DIM)
    output.append("  ", style="default")


def _finding_count_label(finding_count: int) -> str:
    suffix = "s" if finding_count != 1 else ""
    return f" finding{suffix}"


class WorkerList(Widget, can_focus=True):
    """Scrollable selectable list of sweep workers with status indicators."""

    DEFAULT_CSS = """
    WorkerList {
        height: 1fr;
        border: round $accent;
    }

    WorkerList > VerticalScroll {
        height: 1fr;
        padding: 1 2;
    }

    WorkerList:focus {
        border: round $accent-lighten-2;
    }
    """

    BORDER_TITLE = "Workers"

    BINDINGS = [
        ("up", "cursor_up", "Previous worker"),
        ("down", "cursor_down", "Next worker"),
        ("pageup", "page_up", "Previous page"),
        ("pagedown", "page_down", "Next page"),
        ("enter", "select_worker", "Drill into worker"),
    ]

    class WorkerSelected(Message):
        def __init__(self, worker_id: int) -> None:
            super().__init__()
            self.worker_id = worker_id

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._workers: list[WorkerState] = []
        self._rows: list[WorkerRow] = []
        self._cursor_index = 0

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="worker-scroll"):
            yield Static("  (no workers)", id="workers-empty")

    @property
    def _scroll_container(self) -> VerticalScroll:
        return self.query_one("#worker-scroll", VerticalScroll)

    def set_workers(self, labels: list[str]) -> None:
        for row in self._rows:
            row.remove()
        self._workers = [
            WorkerState(worker_id=idx, label=label) for idx, label in enumerate(labels)
        ]
        self._rows = [WorkerRow(worker) for worker in self._workers]
        self._cursor_index = 0

        empty = self.query("#workers-empty")
        if empty:
            empty.first().remove()
        self._scroll_container.mount_all(self._rows)
        self._update_selection()

    def update_worker(
        self,
        worker_id: int,
        *,
        status: WorkerStatus | None = None,
        finding_count: int | None = None,
        tool_call_count: int | None = None,
        elapsed_seconds: float | None = None,
        last_tool_call: str | None = None,
    ) -> None:
        if 0 <= worker_id < len(self._workers):
            worker = self._workers[worker_id]
            if status is not None:
                worker.status = status
            if finding_count is not None:
                worker.finding_count = finding_count
            if tool_call_count is not None:
                worker.tool_call_count = tool_call_count
            if elapsed_seconds is not None:
                worker.elapsed_seconds = elapsed_seconds
            if last_tool_call is not None:
                worker.last_tool_call = last_tool_call
            self._rows[worker_id].refresh(layout=True)

    def action_cursor_up(self) -> None:
        if self._cursor_index > 0:
            self._cursor_index -= 1
            self._update_selection()

    def action_cursor_down(self) -> None:
        if self._cursor_index < len(self._workers) - 1:
            self._cursor_index += 1
            self._update_selection()

    def action_page_up(self) -> None:
        if not self._workers:
            return
        page = self._page_size()
        self._cursor_index = max(0, self._cursor_index - page)
        self._update_selection()

    def action_page_down(self) -> None:
        if not self._workers:
            return
        page = self._page_size()
        self._cursor_index = min(len(self._workers) - 1, self._cursor_index + page)
        self._update_selection()

    def action_select_worker(self) -> None:
        if self._workers:
            self.post_message(self.WorkerSelected(self._cursor_index))

    @property
    def worker_count(self) -> int:
        return len(self._workers)

    def get_worker_info(self, worker_id: int) -> tuple[str, WorkerStatus] | None:
        if 0 <= worker_id < len(self._workers):
            worker = self._workers[worker_id]
            return worker.label, worker.status
        return None

    def _update_selection(self) -> None:
        for idx, row in enumerate(self._rows):
            was_selected = row.selected
            row.selected = idx == self._cursor_index
            if row.selected or was_selected:
                row.refresh(layout=True)
        if 0 <= self._cursor_index < len(self._rows):
            selected = self._rows[self._cursor_index]
            self.call_after_refresh(selected.scroll_visible, animate=False)

    def _page_size(self) -> int:
        return max(1, (self._scroll_container.size.height or 2) // 2)
