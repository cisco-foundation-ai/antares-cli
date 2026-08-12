# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Main Textual app for the antares TUI."""

from __future__ import annotations

from collections.abc import Callable

from textual.app import App

from antares_cli.tui.screens.sweep import SweepOverviewScreen, WorkerDetailScreen


class AntaresApp(App[None]):
    """The Antares sweep TUI application."""

    CSS = """
    Screen {
        background: $surface;
    }

    HeaderBar {
        border: round #444444;
    }

    ActivityPanel {
        border: round #444444;
    }

    FindingsPanel {
        border: round #444444;
    }

    WorkerList {
        border: round #444444;
    }

    WorkerList:focus {
        border: round #66ddff;
    }
    """

    TITLE = "antares"

    def __init__(
        self,
        *,
        profile: str = "",
        target: str = "",
        sweep_label: str = "",
        worker_count: int = 0,
        on_ready: Callable[[], None] | None = None,
        on_drill_in: Callable[[WorkerDetailScreen], None] | None = None,
    ) -> None:
        super().__init__()
        self._profile = profile
        self._target = target
        self._sweep_label = sweep_label
        self._worker_count = worker_count
        self._on_ready = on_ready
        self._on_drill_in = on_drill_in

    def on_mount(self) -> None:
        screen = SweepOverviewScreen(
            profile=self._profile,
            target=self._target,
            sweep_label=self._sweep_label,
            worker_count=self._worker_count,
            on_drill_in=self._on_drill_in,
        )
        self.push_screen(screen)
        if self._on_ready is not None:
            self.call_after_refresh(self._on_ready)
