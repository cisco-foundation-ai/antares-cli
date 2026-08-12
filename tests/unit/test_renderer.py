# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel

from antares_cli.output.finding import Finding, ReportSummary
from antares_cli.output.renderer import (
    render_finding_card,
    render_summary_panel,
)


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, Any] = {
        "title": "SQL Injection",
        "file_path": "app.py",
        "cwe_ids": ["CWE-89"],
        "confidence": 0.95,
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _make_summary(**overrides: object) -> ReportSummary:
    defaults: dict[str, Any] = {
        "total_findings": 3,
        "tool_call_count": 10,
        "duration_seconds": 4.5,
        "investigation_trace": "/tmp/trace.investigation.jsonl",
        "cwe_ids_triggered": ["CWE-89", "CWE-79"],
        "total_workers": 2,
    }
    defaults.update(overrides)
    return ReportSummary(**defaults)


def _render_to_text(renderable: object, *, width: int = 120) -> str:
    text_console = Console(record=True, width=width, force_terminal=False)
    text_console.print(renderable)
    return text_console.export_text()


def test_render_finding_card_returns_panel() -> None:
    finding = _make_finding()
    result = render_finding_card(finding)
    assert isinstance(result, Panel)


def test_render_finding_card_contains_title() -> None:
    finding = _make_finding()
    rendered = _render_to_text(render_finding_card(finding))
    assert "SQL Injection" in rendered


def test_render_finding_card_uses_complete_field_names() -> None:
    finding = _make_finding(
        submission_rank=2,
        likelihood_of_exploit="High",
    )

    rendered = _render_to_text(render_finding_card(finding))

    for key in (
        "Title",
        "File path",
        "Submission rank",
        "CWE IDs",
        "Likelihood of exploit",
    ):
        assert key in rendered


def test_render_finding_card_shows_cwe() -> None:
    finding = _make_finding(cwe_ids=["CWE-89"])
    rendered = _render_to_text(render_finding_card(finding))
    assert "CWE-89" in rendered


def test_render_finding_card_shows_submission_rank() -> None:
    finding = _make_finding(submission_rank=2)
    rendered = _render_to_text(render_finding_card(finding))
    assert "Submission rank" in rendered
    assert "2" in rendered


def test_render_finding_card_folds_long_location_instead_of_truncating() -> None:
    location = "app/apis/orders/really/deep/services/get_order_status.py"
    finding = _make_finding(file_path=location)

    rendered = _render_to_text(render_finding_card(finding), width=60)
    content = "".join(rendered.replace("│", "").split())

    assert "…" not in rendered
    assert location in content


def test_render_summary_panel_shows_totals() -> None:
    summary = _make_summary()
    findings = [_make_finding(), _make_finding(file_path="other.py")]
    rendered = _render_to_text(render_summary_panel(summary, findings=findings))
    assert "3" in rendered
    assert "2" in rendered
    assert "10" in rendered
    assert "4.50s" in rendered


def test_render_summary_panel_uses_complete_field_names() -> None:
    rendered = _render_to_text(render_summary_panel(_make_summary()))

    for key in (
        "Status",
        "Findings",
        "Affected files",
        "CWEs checked",
        "CWE IDs with findings",
        "Duration",
        "Total tool calls",
        "Investigation trace",
    ):
        assert key in rendered


def test_render_summary_panel_marks_incomplete_scans() -> None:
    rendered = _render_to_text(
        render_summary_panel(_make_summary(generation_errors=1), findings=[])
    )

    assert "Incomplete" in rendered
    assert "Generation errors" in rendered


def test_render_summary_panel_shows_investigation_trace() -> None:
    summary = _make_summary(investigation_trace="/tmp/trace.investigation.jsonl")
    rendered = _render_to_text(render_summary_panel(summary))
    assert "Investigation trace" in rendered
    assert "/tmp/trace.investigation.jsonl" in rendered


def test_render_summary_panel_folds_long_trace_instead_of_truncating() -> None:
    investigation_trace = (
        "/home/developer/.local/share/antares-cli/traces/"
        "sample-project-1234567890.investigation.jsonl"
    )
    summary = _make_summary(investigation_trace=investigation_trace)

    rendered = _render_to_text(render_summary_panel(summary), width=72)
    content = "".join(rendered.replace("│", "").split())

    assert "…" not in rendered
    assert investigation_trace in content


def test_render_summary_panel_shows_sweep_investigation_traces() -> None:
    summary = _make_summary(investigation_trace=None)
    rendered = _render_to_text(
        render_summary_panel(
            summary,
            per_cwe_results=[
                {
                    "cwe_id": "CWE-89",
                    "investigation_trace": "/tmp/cwe-89.investigation.jsonl",
                }
            ],
        )
    )
    assert "Investigation trace" in rendered
    assert "CWE-89: /tmp/cwe-89.investigation.jsonl" in rendered


def test_render_summary_panel_shows_context_usage() -> None:
    summary = _make_summary()
    rendered = _render_to_text(render_summary_panel(summary, context_usage_percent=52))
    assert "52%" in rendered
