# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prompt-toolkit directory browser used by the setup wizard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl


class DirectoryBrowser:
    """Interactive directory browser with fuzzy filtering."""

    _MAX_VISIBLE = 12

    def __init__(self, start: Path | None = None) -> None:
        self.current_dir = start or Path.cwd()
        self.selected_index = 0
        self.filter_text = ""
        self.all_entries: list[Path] = []
        self.visible_entries: list[Path] = []

    def run(self) -> Path | None:
        self._refresh_entries()
        control = FormattedTextControl(self._formatted_text)
        layout = Layout(Window(content=control, always_hide_cursor=True, wrap_lines=True))
        app: Application[Path | None] = Application(
            layout=layout,
            key_bindings=self._bindings(),
            full_screen=False,
        )
        return app.run()

    def _refresh_entries(self) -> None:
        self.all_entries = _list_visible_children(self.current_dir)
        self.filter_text = ""
        self._apply_filter()

    def _apply_filter(self) -> None:
        self.visible_entries = [
            entry
            for entry in self.all_entries
            if not self.filter_text or _fuzzy_match(self.filter_text, entry.name)
        ]
        self.selected_index = min(
            self.selected_index,
            max(0, len(self.visible_entries) - 1),
        )

    def _bindings(self) -> KeyBindings:
        bindings = KeyBindings()
        bindings.add("up")(self._move_up)
        bindings.add("down")(self._move_down)
        bindings.add("right")(self._drill_in)
        bindings.add("enter")(self._select)
        bindings.add("left")(self._go_up)
        bindings.add("backspace")(self._backspace)
        bindings.add("tab")(self._select_current_dir)
        bindings.add("c-c")(self._cancel)
        bindings.add("escape")(self._cancel)
        bindings.add("<any>")(self._type_char)
        return bindings

    def _move_up(self, event: Any) -> None:
        if self.visible_entries:
            self.selected_index = (self.selected_index - 1) % len(self.visible_entries)

    def _move_down(self, event: Any) -> None:
        if self.visible_entries:
            self.selected_index = (self.selected_index + 1) % len(self.visible_entries)

    def _drill_in(self, event: Any) -> None:
        selected = self._selected_entry()
        if selected is not None and selected.is_dir():
            self.current_dir = selected
            self.selected_index = 0
            self._refresh_entries()

    def _select(self, event: Any) -> None:
        selected = self._selected_entry()
        if selected is not None and selected.is_dir():
            event.app.exit(result=selected)
        else:
            event.app.exit(result=self.current_dir)

    def _go_up(self, event: Any) -> None:
        self._move_to_parent()

    def _backspace(self, event: Any) -> None:
        if self.filter_text:
            self.filter_text = self.filter_text[:-1]
            self._apply_filter()
            return
        self._move_to_parent()

    def _select_current_dir(self, event: Any) -> None:
        event.app.exit(result=self.current_dir)

    def _cancel(self, event: Any) -> None:
        event.app.exit(result=None)

    def _type_char(self, event: Any) -> None:
        char = event.data
        if char.isprintable() and len(char) == 1:
            self.filter_text += char
            self.selected_index = 0
            self._apply_filter()

    def _move_to_parent(self) -> None:
        parent = self.current_dir.parent
        if parent == self.current_dir:
            return
        self.current_dir = parent
        self.selected_index = 0
        self._refresh_entries()

    def _selected_entry(self) -> Path | None:
        if not self.visible_entries:
            return None
        return self.visible_entries[self.selected_index]

    def _formatted_text(self) -> FormattedText:
        lines: list[tuple[str, str]] = []
        self._append_header(lines)
        self._append_entry_window(lines)
        lines.append(("", "\n"))
        lines.append(("ansigray", _HELP_TEXT))
        return FormattedText(lines)

    def _append_header(self, lines: list[tuple[str, str]]) -> None:
        lines.append(("bold", "  Target directory\n"))
        lines.append(("ansibrightcyan", f"  {self.current_dir}\n"))
        if self.filter_text:
            lines.append(("ansibrightyellow", f"  filter: {self.filter_text}"))
            lines.append(("ansigray", _match_count_text(len(self.visible_entries))))
        else:
            lines.append(("ansigray", "  ─────────────────────────────────────────\n"))

    def _append_entry_window(self, lines: list[tuple[str, str]]) -> None:
        if not self.visible_entries:
            lines.append(("ansigray", "    (no matches)\n"))
            return
        window_start, window_end = _visible_window(
            selected_index=self.selected_index,
            entry_count=len(self.visible_entries),
            max_visible=self._MAX_VISIBLE,
        )
        self._append_above_marker(lines, window_start)
        self._append_visible_entries(lines, window_start, window_end)
        self._append_below_marker(lines, window_end)

    def _append_above_marker(self, lines: list[tuple[str, str]], window_start: int) -> None:
        if window_start > 0:
            lines.append(("ansigray", f"    ··· {window_start} more above\n"))

    def _append_visible_entries(
        self, lines: list[tuple[str, str]], window_start: int, window_end: int
    ) -> None:
        for index in range(window_start, window_end):
            entry = self.visible_entries[index]
            lines.append(_entry_line(entry, selected=index == self.selected_index))

    def _append_below_marker(self, lines: list[tuple[str, str]], window_end: int) -> None:
        remaining = len(self.visible_entries) - window_end
        if remaining > 0:
            lines.append(("ansigray", f"    ··· {remaining} more below\n"))


def _list_visible_children(directory: Path) -> list[Path]:
    try:
        return [
            child
            for child in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            if not child.name.startswith(".")
        ]
    except PermissionError:
        return []


def _fuzzy_match(query: str, name: str) -> bool:
    name_lower = name.lower()
    idx = 0
    for char in query.lower():
        found = name_lower.find(char, idx)
        if found == -1:
            return False
        idx = found + 1
    return True


def _match_count_text(match_count: int) -> str:
    suffix = "es" if match_count != 1 else ""
    return f"  ({match_count} match{suffix})\n"


def _visible_window(*, selected_index: int, entry_count: int, max_visible: int) -> tuple[int, int]:
    window_start = max(0, selected_index - max_visible // 2)
    window_end = min(entry_count, window_start + max_visible)
    if window_end - window_start < max_visible:
        window_start = max(0, window_end - max_visible)
    return window_start, window_end


def _entry_line(entry: Path, *, selected: bool) -> tuple[str, str]:
    is_dir = entry.is_dir()
    name = f"{entry.name}/" if is_dir else entry.name
    if selected:
        style = "ansibrightcyan bold" if is_dir else "ansibrightcyan"
        return style, f"  ❯ {name}\n"
    style = "ansibrightyellow" if is_dir else "ansigray"
    return style, f"    {name}\n"


_HELP_TEXT = "  ↑↓ navigate · → open · enter select · ← back · tab select cwd · type to filter"
