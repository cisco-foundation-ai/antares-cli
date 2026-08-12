# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Findings panel — scrollable list of finding cards with deduplication."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static

from antares_cli.output.finding import Finding, finding_sort_key
from antares_cli.tui.theme import ACCENT, CHROME_DIM, SEVERITY_COLORS


def _dedup_key(finding: Finding) -> tuple[str, str]:
    """Key for identifying duplicate findings across workers."""
    return (finding.file_path, frozenset(finding.cwe_ids).__repr__())


def _display_path(file_path: str) -> str:
    """Normalize separators without shortening the displayed path."""
    return file_path.replace("\\", "/")


def _append_title(
    output: Text,
    finding: Finding,
    confirmed_count: int,
) -> None:
    output.append(finding.title, style="bold")
    if confirmed_count > 1:
        output.append(f"  ×{confirmed_count}", style=f"bold {ACCENT}")
    output.append("\n")


def _append_location(output: Text, finding: Finding, _workspace_root: str) -> None:
    location = _display_path(finding.file_path)
    output.append(location, style="default")
    output.append("\n")


def _append_tags_and_likelihood(output: Text, finding: Finding) -> None:
    tags: list[str] = []
    if finding.submission_rank is not None:
        tags.append(f"rank {finding.submission_rank}")
    if finding.cwe_ids:
        tags.extend(finding.cwe_ids)
    if tags:
        output.append(" · ".join(tags), style=CHROME_DIM)
    if finding.likelihood_of_exploit:
        likelihood_style = {
            "High": f"bold {SEVERITY_COLORS['high']}",
            "Medium": f"bold {SEVERITY_COLORS['medium']}",
            "Low": CHROME_DIM,
        }.get(finding.likelihood_of_exploit, CHROME_DIM)
        if tags:
            output.append("  ")
        output.append(f"⚡{finding.likelihood_of_exploit}", style=likelihood_style)


class FindingCard(Static):
    """A single finding rendered as a compact card."""

    DEFAULT_CSS = """
    FindingCard {
        height: auto;
        width: 1fr;
        padding: 0 1 0 2;
        margin: 0 0 1 0;
    }

    FindingCard {
        border-left: outer #44bbdd;
    }
    """

    def __init__(
        self,
        finding: Finding,
        workspace_root: str = "",
        confirmed_count: int = 1,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._finding = finding
        self._workspace_root = workspace_root
        self._confirmed_count = confirmed_count

    def render(self) -> Text:
        finding = self._finding
        output = Text(overflow="fold")

        _append_title(output, finding, self._confirmed_count)
        _append_location(output, finding, self._workspace_root)
        _append_tags_and_likelihood(output, finding)

        return output


class FindingsPanel(Widget):
    """Right panel showing accumulated findings as scrollable, deduplicated cards."""

    DEFAULT_CSS = """
    FindingsPanel {
        height: 1fr;
        border: round $accent;
    }

    FindingsPanel > VerticalScroll {
        height: 1fr;
        padding: 1 1;
    }
    """

    BORDER_TITLE = "Findings"

    def __init__(
        self,
        workspace_root: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._findings: list[Finding] = []
        self._cards: list[FindingCard] = []
        self._dedup_map: dict[tuple[str, str], int] = {}
        self._workspace_root = workspace_root

    def set_workspace_root(self, workspace_root: str) -> None:
        self._workspace_root = workspace_root

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="findings-scroll"):
            yield Static("  (none yet)", id="findings-empty")

    @property
    def _scroll_container(self) -> VerticalScroll:
        return self.query_one("#findings-scroll", VerticalScroll)

    def _sort_key(self, finding: Finding) -> tuple[str, bool, int, str, str]:
        return finding_sort_key(finding)

    def push_finding(
        self,
        finding: Finding,
        *,
        focus_cwe_ids: list[str] | None = None,
    ) -> None:
        self._findings.append(finding)

        key = _dedup_key(finding)
        if key in self._dedup_map:
            card_index = self._dedup_map[key]
            card = self._cards[card_index]
            card._confirmed_count += 1
            card.refresh()
            return

        empty = self.query("#findings-empty")
        if empty:
            empty.first().remove()

        insert_index = 0
        for i, existing in enumerate(self._cards):
            if self._sort_key(finding) >= self._sort_key(existing._finding):
                insert_index = i + 1
            else:
                break
        else:
            insert_index = len(self._cards)

        card = FindingCard(
            finding,
            workspace_root=self._workspace_root,
        )
        if insert_index >= len(self._cards):
            self._scroll_container.mount(card)
        else:
            self._scroll_container.mount(card, before=self._cards[insert_index])
        self._cards.insert(insert_index, card)
        self._dedup_map[key] = insert_index
        for k, v in self._dedup_map.items():
            if k != key and v >= insert_index:
                self._dedup_map[k] = v + 1
        self._scroll_container.scroll_end(animate=False)

    @property
    def count(self) -> int:
        return len(self._findings)
