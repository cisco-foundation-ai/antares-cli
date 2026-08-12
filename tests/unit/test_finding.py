# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import stat

import pytest
from rich.console import Console

from antares_cli.output.finding import Finding, ReportSummary, deduplicate_findings
from antares_cli.output.renderer import render_finding_card, render_summary_panel
from antares_cli.output.report import (
    serialize_report_json,
    serialize_report_markdown,
    serialize_report_sarif,
    write_report,
)


def test_finding_serialization_and_thresholds(snapshot) -> None:
    finding = Finding(
        title="SQL Injection",
        file_path="app.py",
        cwe_ids=["CWE-89"],
        confidence=0.95,
        submission_rank=1,
    )
    summary = ReportSummary(
        total_findings=1,
        tool_call_count=3,
        duration_seconds=1.2,
        investigation_trace="/tmp/trace.investigation.jsonl",
        cwe_ids_triggered=["CWE-89"],
    )

    console = Console(record=True, width=100)
    console.print(render_finding_card(finding))
    console.print(render_summary_panel(summary, findings=[finding]))
    rendered_text = console.export_text()

    report_json = serialize_report_json([finding], summary)
    assert report_json
    assert report_json.lstrip().startswith('{\n  "summary"')
    assert "confidence" not in report_json
    json_payload = json.loads(report_json)
    serialized_finding = json_payload["findings"][0]
    assert "investigation_trace" not in json_payload["summary"]
    assert set(serialized_finding) == {
        "title",
        "file_path",
        "cwe_ids",
        "submission_rank",
        "likelihood_of_exploit",
    }
    assert serialized_finding["submission_rank"] == 1
    assert "SQL Injection" in serialize_report_markdown([finding], summary)
    assert "Submission rank: 1" in serialize_report_markdown([finding], summary)
    assert "CWE\\-89 — Improper Neutralization" in serialize_report_markdown([finding], summary)
    assert "trace.investigation.jsonl" not in serialize_report_markdown([finding], summary)
    sarif_payload = json.loads(serialize_report_sarif([finding], summary))
    sarif_result = sarif_payload["runs"][0]["results"][0]
    sarif_rule = sarif_payload["runs"][0]["tool"]["driver"]["rules"][0]
    assert sarif_result["ruleId"] == "CWE-89"
    assert sarif_rule["name"].startswith("Improper Neutralization")
    assert "region" not in sarif_result["locations"][0]["physicalLocation"]
    assert set(sarif_result["properties"]) == {
        "title",
        "cweIds",
        "submissionRank",
        "likelihoodOfExploit",
    }
    assert "investigation_trace" not in sarif_payload["runs"][0]["invocations"][0]["properties"]
    assert rendered_text == snapshot


def test_reports_use_supported_finding_schema() -> None:
    finding = Finding(
        title="Submitted vulnerable file",
        file_path="app.py",
        cwe_ids=[],
        confidence=0.95,
    )
    summary = ReportSummary(
        total_findings=1,
        tool_call_count=3,
        duration_seconds=1.2,
        cwe_ids_triggered=[],
    )

    report = serialize_report_markdown([finding], summary)
    serialized_finding = json.loads(serialize_report_json([finding], summary))["findings"][0]

    assert "### `app.py` — 1 finding" in report
    assert "#### Unclassified" in report
    assert set(serialized_finding) == {
        "title",
        "file_path",
        "cwe_ids",
        "likelihood_of_exploit",
    }
    assert "submission_rank" not in serialized_finding


def test_report_paths_cannot_inject_markdown_or_raw_sarif_controls() -> None:
    malicious_path = "src/evil`name.py\n## Forged section"
    finding = Finding(
        title="Submitted vulnerable file",
        file_path=malicious_path,
        cwe_ids=["CWE-89"],
        confidence=0.9,
    )
    summary = ReportSummary(
        total_findings=1,
        tool_call_count=1,
        duration_seconds=0.1,
        cwe_ids_triggered=["CWE-89"],
    )

    markdown = serialize_report_markdown([finding], summary)
    sarif = json.loads(serialize_report_sarif([finding], summary))
    sarif_uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]

    assert "\n## Forged section" not in markdown
    assert r"\n## Forged section" in markdown
    assert "%0A%23%23%20Forged%20section" in sarif_uri
    assert "\n" not in sarif_uri


def test_sweep_investigation_traces_are_omitted_from_shareable_reports() -> None:
    summary = ReportSummary(
        total_findings=0,
        tool_call_count=2,
        duration_seconds=1.2,
        cwe_ids_triggered=[],
    )
    per_cwe_results = [
        {
            "cwe_id": "CWE-89",
            "finding_count": 0,
            "investigation_trace": "/tmp/cwe-89.investigation.jsonl",
        }
    ]

    json_payload = json.loads(serialize_report_json([], summary, per_cwe_results=per_cwe_results))
    markdown = serialize_report_markdown([], summary, per_cwe_results=per_cwe_results)
    sarif_payload = json.loads(serialize_report_sarif([], summary, per_cwe_results=per_cwe_results))
    assert "investigation_trace" not in json_payload["per_cwe_results"][0]
    assert "cwe-89.investigation.jsonl" not in markdown
    sarif_worker = sarif_payload["runs"][0]["invocations"][0]["properties"]["per_cwe_results"][0]
    assert "investigation_trace" not in sarif_worker
    assert "CWE\\-89 — Improper Neutralization" in markdown
    assert "No findings reported" in markdown


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_written_reports_are_private(tmp_path) -> None:
    summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=0.1,
        cwe_ids_triggered=[],
    )
    report_path = write_report(tmp_path / "report.json", [], summary, output_format="json")

    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".report.json-*.tmp")) == []


def test_zero_finding_reports_use_neutral_wording_even_when_incomplete() -> None:
    summaries = [
        ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=1.0,
            cwe_ids_triggered=[],
            generation_errors=1,
        ),
        ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=1.0,
            cwe_ids_triggered=[],
            incomplete_reason="Model ended without an explicit final submission.",
        ),
    ]

    for summary in summaries:
        markdown = serialize_report_markdown([], summary)

        assert "Status: Incomplete" in markdown
        assert "clean" not in markdown.lower()
        assert "No findings were reported." in markdown
        assert "No findings were identified." not in markdown


def test_markdown_groups_findings_by_filename_before_cwe() -> None:
    findings = [
        Finding("SQL injection", "z.py", ["CWE-89"], 0.9),
        Finding("Cross-site scripting", "a.py", ["CWE-79"], 0.9),
        Finding("Another injection", "a.py", ["CWE-89"], 0.8),
    ]
    summary = ReportSummary(
        total_findings=3,
        tool_call_count=2,
        duration_seconds=1.0,
        cwe_ids_triggered=["CWE-79", "CWE-89"],
    )

    markdown = serialize_report_markdown(findings, summary)

    a_file = markdown.index("### `a.py`")
    z_file = markdown.index("### `z.py`")
    assert a_file < z_file
    assert markdown.index("CWE\\-79", a_file) < markdown.index("CWE\\-89", a_file)


def test_findings_are_ordered_by_local_submission_rank() -> None:
    second = Finding(
        title="Second",
        file_path="a.py",
        cwe_ids=["CWE-89"],
        confidence=0.9,
        submission_rank=2,
    )
    first = Finding(
        title="First",
        file_path="z.py",
        cwe_ids=["CWE-89"],
        confidence=0.95,
        submission_rank=1,
    )

    ordered = deduplicate_findings([second, first])

    assert [finding.file_path for finding in ordered] == ["z.py", "a.py"]


def test_distinct_monorepo_paths_are_not_collapsed_by_suffix() -> None:
    findings = [
        Finding("Root auth issue", "src/auth.py", ["CWE-89"], 0.9),
        Finding("API auth issue", "packages/api/src/auth.py", ["CWE-89"], 0.95),
    ]

    deduplicated = deduplicate_findings(findings)

    assert {finding.file_path for finding in deduplicated} == {
        "src/auth.py",
        "packages/api/src/auth.py",
    }


def test_equivalent_paths_with_the_same_cwe_keep_the_highest_confidence() -> None:
    lower = Finding("Lower confidence", "./src/auth.py", ["89"], 0.7)
    higher = Finding("Higher confidence", "src/auth.py", ["CWE-89"], 0.95)

    deduplicated = deduplicate_findings([lower, higher])

    assert deduplicated == [higher]
    assert deduplicated[0].file_path == "src/auth.py"


def test_same_file_with_distinct_cwe_scopes_remains_distinct() -> None:
    findings = [
        Finding("SQL injection", "src/app.py", ["CWE-89"], 0.9),
        Finding("Cross-site scripting", "src/app.py", ["CWE-79"], 0.9),
    ]

    assert len(deduplicate_findings(findings)) == 2
