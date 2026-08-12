# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Header bar widget — shows mode, profile, target."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from antares_cli.tui.theme import ACCENT, ACCENT_BOLD, CHROME_DIM, SUCCESS


class HeaderBar(Static):
    """Single-line header: ● antares · mode · profile · target."""

    DEFAULT_CSS = """
    HeaderBar {
        height: auto;
        min-height: 3;
        padding: 0 2;
        content-align: left middle;
        background: $surface;
        border: round $accent;
    }
    """

    def __init__(
        self,
        mode: str,
        profile: str = "",
        target: str = "",
        extra: str = "",
    ) -> None:
        super().__init__()
        self._mode = mode
        self._profile = profile
        self._target = target
        self._extra = extra

    def render(self) -> Text:
        header = Text(overflow="fold")
        header.append("● ", style=f"bold {SUCCESS}")
        header.append("antares", style=f"bold {ACCENT_BOLD}")
        header.append("  ·  ", style=CHROME_DIM)
        header.append(self._mode, style=f"bold {ACCENT_BOLD}")
        if self._profile:
            header.append("  ·  ", style=CHROME_DIM)
            header.append(self._profile, style=ACCENT)
        if self._extra:
            header.append("  ·  ", style=CHROME_DIM)
            header.append(self._extra, style=ACCENT)
        if self._target:
            header.append("  ·  ", style=CHROME_DIM)
            header.append(self._target, style=ACCENT)
        return header
