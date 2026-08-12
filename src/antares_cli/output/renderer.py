# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Rich renderers for findings and agent state."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from antares_cli.output.finding import Finding, ReportSummary, TrajectoryEntry


@dataclass(slots=True)
class AgentStateSnapshot:
    context_usage_percent: int
    trajectory: list[TrajectoryEntry] = field(default_factory=list)


def render_key_value_panel(
    title: str,
    rows: Sequence[tuple[str, object]],
    *,
    border_style: str = "cyan",
) -> Panel:
    """Render complete keys and values, folding long values instead of truncating."""
    return Panel(_key_value_table(rows), title=title, border_style=border_style)


def _key_value_table(rows: Sequence[tuple[str, object]]) -> Table:
    table = Table.grid(padding=(0, 1))
    label_width = max((len(label) for label, _ in rows), default=0)
    table.add_column(width=label_width, no_wrap=True)
    table.add_column(overflow="fold")
    for label, value in rows:
        if isinstance(value, Text):
            rendered_value = value.copy()
            rendered_value.overflow = "fold"
        else:
            rendered_value = Text(str(value), overflow="fold")
        table.add_row(Text(label, style="bold"), rendered_value)
    return table


def render_finding_card(finding: Finding) -> Panel:
    title = Text(finding.title, style="bold")
    rows: list[tuple[str, object]] = [
        ("Title", title),
        ("File path", finding.file_path),
    ]

    if finding.submission_rank is not None:
        rows.append(("Submission rank", finding.submission_rank))

    classification_parts = Text()
    if finding.cwe_ids:
        classification_parts.append(", ".join(finding.cwe_ids))
    if not finding.cwe_ids:
        classification_parts.append("None", style="dim")
    rows.append(("CWE IDs", classification_parts))

    if finding.likelihood_of_exploit:
        likelihood_style = {
            "High": "bold red",
            "Medium": "yellow",
            "Low": "green dim",
        }.get(finding.likelihood_of_exploit, "default")
        rows.append(
            (
                "Likelihood of exploit",
                Text(finding.likelihood_of_exploit, style=likelihood_style),
            )
        )

    return Panel(_key_value_table(rows), title="FINDING", border_style="cyan")


def render_summary_panel(
    summary: ReportSummary,
    *,
    findings: list[Finding] | None = None,
    checked_cwe_ids: list[str] | None = None,
    context_usage_percent: int | None = None,
    per_cwe_results: list[dict[str, Any]] | None = None,
) -> Panel:
    has_operational_failures = (
        summary.generation_errors > 0
        or summary.failed_workers > 0
        or summary.incomplete_reason is not None
    )
    affected_file_count = len({finding.file_path for finding in findings or []})
    checked_cwe_count = (
        len(per_cwe_results or [])
        or len(checked_cwe_ids or [])
        or summary.total_workers
        or len(summary.cwe_ids_triggered)
    )
    rows: list[tuple[str, object]] = [
        (
            "Status",
            Text(
                "Incomplete" if has_operational_failures else "Complete",
                style="bold red" if has_operational_failures else "bold green",
            ),
        ),
        ("Findings", summary.total_findings),
        ("Affected files", affected_file_count),
        ("CWEs checked", checked_cwe_count),
        (
            "CWE IDs with findings",
            ", ".join(summary.cwe_ids_triggered) if summary.cwe_ids_triggered else "None",
        ),
        ("Duration", f"{summary.duration_seconds:.2f}s"),
        ("Total tool calls", summary.tool_call_count),
    ]

    if summary.investigation_trace:
        rows.append(
            (
                "Investigation trace",
                Text(summary.investigation_trace, style="dim"),
            )
        )

    for entry in per_cwe_results or []:
        investigation_trace = entry.get("investigation_trace")
        if not isinstance(investigation_trace, str) or not investigation_trace:
            continue
        cwe_id = entry.get("cwe_id")
        label = cwe_id if isinstance(cwe_id, str) and cwe_id else "worker"
        rows.append(
            (
                "Investigation trace",
                Text(f"{label}: {investigation_trace}", style="dim"),
            )
        )

    if context_usage_percent is not None:
        context_bar = _build_labeled_usage_bar("Context", context_usage_percent)
        rows.append(("Context usage", context_bar))

    if getattr(summary, "failed_tool_calls", 0) > 0:
        rows.append(
            (
                "Failed tool calls",
                Text(str(summary.failed_tool_calls), style="yellow"),
            )
        )

    if getattr(summary, "retried_turns", 0) > 0:
        rows.append(
            (
                "Retried turns",
                Text(str(summary.retried_turns), style="yellow"),
            )
        )

    if getattr(summary, "generation_errors", 0) > 0:
        rows.append(
            (
                "Generation errors",
                Text(
                    f"{summary.generation_errors} — model backend error interrupted the scan; "
                    "results may be incomplete",
                    style="bold red",
                ),
            ),
        )

    if getattr(summary, "failed_workers", 0) > 0:
        rows.append(
            (
                "Failed workers",
                Text(
                    f"{summary.failed_workers}/{summary.total_workers} CWE workers failed — "
                    "some vulnerability classes were not scanned",
                    style="bold red",
                ),
            ),
        )

    if summary.incomplete_reason is not None:
        rows.append(
            (
                "Incomplete scan",
                Text(summary.incomplete_reason, style="bold red"),
            )
        )

    return Panel(_key_value_table(rows), title="SCAN SUMMARY", border_style="cyan")


def _build_labeled_usage_bar(label: str, percent: int) -> Text:
    fraction = max(0.0, min(1.0, percent / 100.0))
    total_width = 16
    filled_count = int(fraction * total_width)
    empty_count = total_width - filled_count

    bar = Text()
    bar.append("[")
    bar.append("█" * filled_count, style="green" if percent < 80 else "yellow")
    bar.append("░" * empty_count, style="dim")
    bar.append(f"] {percent}%")
    return bar
