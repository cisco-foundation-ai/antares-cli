# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Help overlay — shows keybinds for the current screen."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

_SWEEP_OVERVIEW_KEYBINDS = [
    ("↑ ↓", "Navigate worker list"),
    ("Enter", "Drill into worker detail"),
    ("s", "Save report (after sweep completes)"),
    ("q / Esc", "Quit"),
    ("?", "Show this help"),
]

_WORKER_DETAIL_KEYBINDS = [
    ("Esc", "Back to sweep overview"),
    ("← →", "Previous / next worker"),
    ("q", "Quit"),
    ("?", "Show this help"),
]


class HelpOverlay(ModalScreen[None]):
    """Modal overlay showing keyboard shortcuts."""

    DEFAULT_CSS = """
    HelpOverlay {
        align: center middle;
    }

    #help-container {
        width: 56;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: round #444444;
        padding: 1 2;
    }

    #help-title {
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }

    #help-body {
        height: auto;
    }

    #help-dismiss {
        text-align: center;
        margin-top: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        ("escape", "dismiss_help", "Close"),
        ("question_mark", "dismiss_help", "Close"),
        ("q", "dismiss_help", "Close"),
    ]

    def __init__(self, mode: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._mode = mode

    def compose(self) -> ComposeResult:
        with Vertical(id="help-container"):
            yield Static("Keyboard Shortcuts", id="help-title")
            yield Static(self._render_keybinds(), id="help-body")
            yield Static("Press ? or Esc to close", id="help-dismiss")

    def _render_keybinds(self) -> Text:
        if self._mode == "sweep-overview":
            binds = _SWEEP_OVERVIEW_KEYBINDS
        else:
            binds = _WORKER_DETAIL_KEYBINDS

        output = Text(overflow="fold")
        max_key_len = max(len(key) for key, _ in binds)
        for key, description in binds:
            output.append(f"  {key.ljust(max_key_len)}  ", style="bold")
            output.append(f"{description}\n", style="default")
        if output.plain.endswith("\n"):
            output.right_crop(1)
        return output

    def action_dismiss_help(self) -> None:
        self.dismiss(None)
