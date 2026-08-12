# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Footer widget — progress bar + stats + keybind hints."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.widgets import Static

from antares_cli.tui.theme import CHROME_DIM, SUCCESS


class FooterBar(Static):
    """Shows progress, stats, and keyboard shortcuts."""

    DEFAULT_CSS = """
    FooterBar {
        height: auto;
        min-height: 2;
        padding: 0 2;
        content-align: left middle;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._files_done = 0
        self._files_total = 0
        self._finding_count = 0
        self._context_percent = 0
        self._elapsed_seconds = 0.0
        self._keybinds: str = ""

    def render(self) -> Text:
        line = Text(overflow="fold")

        if self._files_total > 0:
            fraction = self._files_done / self._files_total
            bar_width = 20
            filled = int(fraction * bar_width)
            empty = bar_width - filled
            line.append(f"{self._files_done}/{self._files_total}", style="bold")
            line.append("  ")
            line.append("━" * filled, style=SUCCESS)
            line.append("░" * empty, style=CHROME_DIM)
        elif self._files_done > 0:
            line.append(f"{self._files_done} files", style="bold")

        if self._finding_count > 0:
            line.append("  ·  ", style=CHROME_DIM)
            line.append(f"{self._finding_count} findings", style="bold")

        if self._context_percent > 0:
            line.append("  ·  ", style=CHROME_DIM)
            line.append(f"ctx {self._context_percent}%", style=CHROME_DIM)

        line.append("  ·  ", style=CHROME_DIM)
        line.append(f"{self._elapsed_seconds:.1f}s", style=CHROME_DIM)

        if self._keybinds:
            line.append("    ", style=CHROME_DIM)
            line.append(self._keybinds, style=CHROME_DIM)

        return line

    def update_progress(
        self,
        *,
        files_done: int | None = None,
        files_total: int | None = None,
        finding_count: int | None = None,
        context_percent: int | None = None,
        elapsed_seconds: float | None = None,
        keybinds: str | None = None,
    ) -> None:
        if files_done is not None:
            self._files_done = files_done
        if files_total is not None:
            self._files_total = files_total
        if finding_count is not None:
            self._finding_count = finding_count
        if context_percent is not None:
            self._context_percent = context_percent
        if elapsed_seconds is not None:
            self._elapsed_seconds = elapsed_seconds
        if keybinds is not None:
            self._keybinds = keybinds
        self.refresh()
