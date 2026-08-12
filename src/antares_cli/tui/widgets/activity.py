# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Activity panel — scrollable log of tool calls and reasoning."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static

from antares_cli.tui.theme import (
    ACTIVITY_COMMAND,
    ACTIVITY_RESULT,
    ACTIVITY_THINKING,
    CHROME_DIM,
    SUCCESS,
)


class ActivityEntry(Static):
    """A complete, wrapping entry in the activity log."""

    DEFAULT_CSS = """
    ActivityEntry {
        height: auto;
        width: 1fr;
        padding: 0 1;
        margin: 0 0 0 0;
    }

    """

    def __init__(
        self,
        entry_type: str,
        content: str,
        workspace_root: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.entry_type = entry_type
        self._content = content
        self.workspace_root = workspace_root

    def render(self) -> Text:
        output = Text(overflow="fold")
        renderer = self._entry_renderers().get(self.entry_type)
        if renderer is not None:
            renderer(output)
        return output

    def _entry_renderers(self) -> dict[str, Callable[[Text], None]]:
        return {
            "command": self._render_command,
            "result": self._render_result,
            "thinking": self._render_thinking,
            "done": self._render_done,
        }

    def _render_command(self, output: Text) -> None:
        tool_name, args_text = self._parse_command(self._content)
        output.append(f"→ {tool_name} ", style=f"bold {ACTIVITY_COMMAND}")
        output.append(args_text, style=CHROME_DIM)

    def _render_result(self, output: Text) -> None:
        self._append_prefixed_lines(output, self._content, ACTIVITY_RESULT)

    def _render_thinking(self, output: Text) -> None:
        content = self._content.strip()
        self._append_prefixed_lines(output, content, f"italic {ACTIVITY_THINKING}")

    def _render_done(self, output: Text) -> None:
        output.append("── ", style=CHROME_DIM)
        output.append("✓ ", style=f"bold {SUCCESS}")
        output.append(self._content, style=f"bold {SUCCESS}")
        output.append(" ──", style=CHROME_DIM)

    @staticmethod
    def _append_prefixed_lines(output: Text, content: str, style: str) -> None:
        for line in content.splitlines():
            output.append("│ ", style=CHROME_DIM)
            output.append(f"{line}\n", style=style)
        if output.plain.endswith("\n"):
            output.right_crop(1)

    @staticmethod
    def _parse_command(text: str) -> tuple[str, str]:
        """Split a command string into tool name and arguments."""
        cleaned = text.lstrip("→ ").strip()
        if cleaned.startswith("bash(command="):
            return "bash", cleaned[len("bash(command=") :].rstrip(")")
        if "(" in cleaned:
            paren_idx = cleaned.index("(")
            return cleaned[:paren_idx], cleaned[paren_idx + 1 :].rstrip(")")
        return "$", cleaned


class CursorWidget(Static):
    """Blinking cursor indicator for liveness."""

    DEFAULT_CSS = """
    CursorWidget {
        height: 1;
        padding: 0 1;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._visible = True
        self._on = True

    def render(self) -> Text:
        if self._visible and self._on:
            return Text("▍", style="bold")
        return Text("")

    def toggle(self) -> None:
        if self._visible:
            self._on = not self._on
            self.refresh(layout=True)

    def set_visible(self, visible: bool) -> None:
        self._visible = visible
        self._on = True
        self.refresh(layout=True)


class ActivityPanel(Widget):
    """Scrollable log of agent activity — tool calls, results, thinking."""

    DEFAULT_CSS = """
    ActivityPanel {
        height: 1fr;
        border: round $accent;
    }

    ActivityPanel > VerticalScroll {
        height: 1fr;
        padding: 0 1;
    }
    """

    BORDER_TITLE = "Activity"

    def __init__(self, workspace_root: str = "", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._auto_scroll = True
        self._entries: list[ActivityEntry] = []
        self._workspace_root = workspace_root

    def set_workspace_root(self, workspace_root: str) -> None:
        self._workspace_root = workspace_root

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="activity-scroll"):
            yield CursorWidget(id="activity-cursor")

    @property
    def _scroll_container(self) -> VerticalScroll:
        return self.query_one("#activity-scroll", VerticalScroll)

    @property
    def _cursor(self) -> CursorWidget:
        return self.query_one("#activity-cursor", CursorWidget)

    def _append_entry(self, entry: ActivityEntry) -> None:
        self._entries.append(entry)
        scroll = self._scroll_container
        scroll.mount(entry, before=self._cursor)
        if self._auto_scroll:
            scroll.scroll_end(animate=False)
            self.call_after_refresh(scroll.scroll_end, animate=False)

    def push_command(self, command: str) -> None:
        self._append_entry(
            ActivityEntry(
                entry_type="command", content=command, workspace_root=self._workspace_root
            )
        )

    def push_result(self, result: str) -> None:
        self._append_entry(
            ActivityEntry(entry_type="result", content=result, workspace_root=self._workspace_root)
        )

    def push_thinking(self, text: str) -> None:
        self._append_entry(
            ActivityEntry(entry_type="thinking", content=text, workspace_root=self._workspace_root)
        )

    def push_done(self, summary: str = "") -> None:
        entry = ActivityEntry(
            entry_type="done",
            content=summary or "inference complete",
        )
        self._entries.append(entry)
        scroll = self._scroll_container
        scroll.mount(entry, before=self._cursor)
        if self._auto_scroll:
            scroll.scroll_end(animate=False)

    def set_cursor_visible(self, visible: bool) -> None:
        self._cursor.set_visible(visible)

    def toggle_cursor(self) -> None:
        self._cursor.toggle()
