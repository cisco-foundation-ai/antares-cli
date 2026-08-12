# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import stat
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from antares_cli.commands._workflow import (
    finalize_and_record_workflow_result,
    resolve_report_directory,
    write_workflow_reports,
)
from antares_cli.core.service import SecurityWorkflowService, WorkflowResult
from antares_cli.main import app
from antares_cli.output.finding import Finding, ReportSummary
from antares_cli.run_history import capture_invocation

runner = CliRunner()


def _workflow_result() -> WorkflowResult:
    finding = Finding(
        title="SQL injection",
        file_path="src/orders.py",
        cwe_ids=["CWE-89"],
        confidence=0.95,
        submission_rank=1,
        likelihood_of_exploit="High",
    )
    return WorkflowResult(
        findings=[finding],
        summary=ReportSummary(
            total_findings=1,
            tool_call_count=4,
            duration_seconds=1.5,
            cwe_ids_triggered=["CWE-89"],
        ),
        metadata={"mode": "query", "model": "test-model", "cwe_ids": ["CWE-89"]},
    )


def test_default_report_directory_uses_private_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))

    report_directory = resolve_report_directory(
        output=None,
        execution_id="run-123",
        reports_enabled=True,
    )

    assert report_directory == tmp_path / "antares-data" / "reports" / "run-123"
    assert not report_directory.exists()


def test_report_bundle_writes_all_formats_by_default(tmp_path: Path) -> None:
    report_directory = tmp_path / "reports" / "run-123"

    written = write_workflow_reports(
        report_directory=report_directory,
        report_formats=("json", "markdown", "sarif"),
        result=_workflow_result(),
    )

    assert written == report_directory
    assert {path.name for path in report_directory.iterdir()} == {
        "report.json",
        "report.md",
        "report.sarif",
    }
    assert (
        json.loads((report_directory / "report.json").read_text(encoding="utf-8"))["summary"][
            "total_findings"
        ]
        == 1
    )
    assert "## Findings by file" in (report_directory / "report.md").read_text(encoding="utf-8")
    assert "## Scan coverage" in (report_directory / "report.md").read_text(encoding="utf-8")


def test_report_bundle_can_write_one_selected_format(tmp_path: Path) -> None:
    report_directory = tmp_path / "json-only"
    report_directory.mkdir()
    (report_directory / "report.md").write_text("stale report", encoding="utf-8")
    (report_directory / "report.sarif").write_text("stale report", encoding="utf-8")

    write_workflow_reports(
        report_directory=report_directory,
        report_formats=("json",),
        result=_workflow_result(),
    )

    assert [path.name for path in report_directory.iterdir()] == ["report.json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_default_report_bundle_is_private(tmp_path: Path) -> None:
    report_directory = tmp_path / "private-reports"

    write_workflow_reports(
        report_directory=report_directory,
        report_formats=("json", "markdown", "sarif"),
        result=_workflow_result(),
    )

    assert stat.S_IMODE(report_directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in report_directory.iterdir())


def test_completion_output_names_formats_and_report_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    report_directory = tmp_path / "reports" / "run-123"
    output = StringIO()
    invocation = capture_invocation(argv=["antares", "query", "."], cwd=tmp_path)

    finalize_and_record_workflow_result(
        _workflow_result(),
        invocation=invocation,
        target=tmp_path,
        report_directory=report_directory,
        report_formats=("json", "markdown", "sarif"),
        stdout_format=None,
        console=Console(file=output, force_terminal=False),
    )

    terminal_output = output.getvalue()
    assert "Reports (JSON, Markdown, SARIF)" in terminal_output
    assert str(report_directory) in terminal_output


def test_query_generates_default_bundle_and_terminal_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "antares-data"
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: _workflow_result(),
    )

    result = runner.invoke(
        app,
        ["query", str(tmp_path), "--cwe", "CWE-89"],
        env={"ANTARES_DATA_DIR": str(data_root)},
    )

    report_directories = list((data_root / "reports").iterdir())
    assert result.exit_code == 0
    assert len(report_directories) == 1
    assert {path.name for path in report_directories[0].iterdir()} == {
        "report.json",
        "report.md",
        "report.sarif",
    }
    assert "SCAN SUMMARY" in result.output
    assert "Reports (JSON, Markdown, SARIF)" in result.output
    assert str(report_directories[0]) in "".join(result.output.split())
    if os.name != "nt":
        assert stat.S_IMODE((data_root / "reports").stat().st_mode) == 0o700


def test_query_can_persist_only_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_directory = tmp_path / "json-report"
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: _workflow_result(),
    )

    result = runner.invoke(
        app,
        [
            "query",
            str(tmp_path),
            "--cwe",
            "CWE-89",
            "--output",
            str(report_directory),
            "--report-format",
            "json",
        ],
        env={"ANTARES_DATA_DIR": str(tmp_path / "antares-data")},
    )

    assert result.exit_code == 0
    assert [path.name for path in report_directory.iterdir()] == ["report.json"]
    assert "Reports (JSON)" in result.output


def test_query_accepts_explicit_all_report_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_directory = tmp_path / "all-reports"
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: _workflow_result(),
    )

    result = runner.invoke(
        app,
        [
            "query",
            str(tmp_path),
            "--cwe",
            "CWE-89",
            "--output",
            str(report_directory),
            "--report-format",
            "all",
        ],
        env={"ANTARES_DATA_DIR": str(tmp_path / "antares-data")},
    )

    assert result.exit_code == 0
    assert {path.name for path in report_directory.iterdir()} == {
        "report.json",
        "report.md",
        "report.sarif",
    }
    assert "Reports (JSON, Markdown, SARIF)" in result.output


def test_stdout_json_remains_machine_readable_while_reports_are_saved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "antares-data"
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: _workflow_result(),
    )

    result = runner.invoke(
        app,
        ["query", str(tmp_path), "--cwe", "CWE-89", "--format", "json"],
        env={"ANTARES_DATA_DIR": str(data_root)},
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["total_findings"] == 1
    assert "Reports (JSON, Markdown, SARIF)" in result.stderr
    assert len(list((data_root / "reports").iterdir())) == 1


def test_no_report_skips_shareable_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "antares-data"
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: _workflow_result(),
    )

    result = runner.invoke(
        app,
        ["query", str(tmp_path), "--cwe", "CWE-89", "--no-report"],
        env={"ANTARES_DATA_DIR": str(data_root)},
    )

    assert result.exit_code == 0
    assert not (data_root / "reports").exists()
    assert "Reports (" not in result.output
