# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public command-surface contracts."""

from __future__ import annotations

import pytest
from rich.text import Text
from typer.main import get_command
from typer.testing import CliRunner

import antares_cli.commands.runs as runs_module
from antares_cli.commands._workflow import repository_artifact_excludes
from antares_cli.core.runtime import RuntimeFactory
from antares_cli.core.service import SecurityWorkflowService
from antares_cli.main import app

runner = CliRunner()


def test_in_repository_reports_and_exports_are_excluded_from_scan_inputs(tmp_path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    excludes = repository_artifact_excludes(
        target=repository,
        output=repository / "reports" / "latest.json",
        export_path=repository / "artifacts" / "trace.tar.gz",
    )

    assert excludes == ["reports/latest.json", "artifacts/trace.tar.gz"]


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "powershell", "pwsh"])
def test_completion_script_uses_the_live_click_completion_protocol(shell: str) -> None:
    result = runner.invoke(app, ["completion", shell])

    assert result.exit_code == 0
    assert result.exception is None
    assert "_ANTARES_COMPLETE" in result.output
    assert "antares" in result.output


def test_completion_rejects_an_unsupported_shell_without_a_traceback() -> None:
    result = runner.invoke(app, ["completion", "tcsh"])

    assert result.exit_code == 2
    assert "Invalid value" in result.output
    assert "Traceback" not in result.output


def test_generated_bash_completion_protocol_returns_live_commands() -> None:
    result = runner.invoke(
        app,
        [],
        env={
            "_ANTARES_COMPLETE": "complete_bash",
            "COMP_WORDS": "antares ",
            "COMP_CWORD": "1",
        },
    )

    assert result.exit_code == 0
    assert "query" in result.output
    assert "sweep" in result.output


def test_root_help_describes_primary_scan_modes() -> None:
    result = runner.invoke(app, ["--help"])
    root_command = get_command(app)

    assert result.exit_code == 0
    assert root_command.commands["query"].help == (
        "Scan a repository for one or more explicit CWE IDs."
    )
    assert root_command.commands["sweep"].help == (
        "Scan a repository across explicit or automatically selected CWE IDs."
    )


def test_sweep_help_exposes_additional_instructions() -> None:
    result = runner.invoke(app, ["sweep", "--help"])
    sweep_command = get_command(app).commands["sweep"]
    query_option = next(
        parameter for parameter in sweep_command.params if "--query" in parameter.opts
    )

    assert result.exit_code == 0
    assert query_option.help == "Additional instructions applied to every CWE investigation."


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_scan_help_exposes_report_bundle_controls(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    plain_output = Text.from_ansi(result.output).plain
    command_definition = get_command(app).commands[command]
    output_option = next(
        parameter for parameter in command_definition.params if "--output" in parameter.opts
    )
    report_format_option = next(
        parameter for parameter in command_definition.params if "--report-format" in parameter.opts
    )

    assert result.exit_code == 0
    assert "--report-format" in plain_output
    assert "--no-report" in plain_output
    assert "Directory for report" in plain_output
    assert "Defaults to" in output_option.help
    assert "Default: all." in report_format_option.help


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_scan_help_exposes_exact_sensitive_file_opt_in(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    command_definition = get_command(app).commands[command]
    sensitive_file_option = next(
        parameter
        for parameter in command_definition.params
        if "--allow-sensitive-file" in parameter.opts
    )

    assert result.exit_code == 0
    assert sensitive_file_option.multiple is True
    assert "exact repository-relative sensitive file" in sensitive_file_option.help


def test_multi_run_export_rejects_a_tar_gzip_output_file(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [{"execution_id": "run-one"}, {"execution_id": "run-two"}]
    monkeypatch.setattr(runs_module, "load_run_records", lambda **_kwargs: records)

    def unexpected_export(*_args, **_kwargs):
        raise AssertionError("multi-run export must reject an archive output path")

    monkeypatch.setattr(runs_module, "export_run_bundles", unexpected_export)
    output_path = tmp_path / "combined.TAR.GZ"

    result = runner.invoke(
        app,
        ["runs", "export", "--last", "2", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "--output must be a directory when exporting multiple runs" in " ".join(
        Text.from_ansi(result.output).plain.split()
    )
    assert not output_path.exists()


def test_run_export_rejects_conflicting_selectors_before_loading_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_load(*_args, **_kwargs):
        raise AssertionError("history must not load for conflicting selectors")

    monkeypatch.setattr(runs_module, "load_run_records", unexpected_load)

    result = runner.invoke(app, ["runs", "export", "run-one", "--all"])

    assert result.exit_code == 2
    assert "run IDs, --last, or --all" in Text.from_ansi(result.output).plain
    assert not isinstance(result.exception, AssertionError)


@pytest.mark.parametrize("command", ["query", "sweep"])
@pytest.mark.parametrize("with_output", [False, True])
def test_invalid_output_format_is_rejected_before_any_scan_work(
    command: str,
    with_output: bool,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("scan service must not run for an invalid output format")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", unexpected_call)
    monkeypatch.setattr(SecurityWorkflowService, "preview_sweep_details", unexpected_call)
    arguments = [command, str(tmp_path), "--format", "yaml"]
    if command == "query":
        arguments.extend(["--cwe", "CWE-89"])
    if with_output:
        arguments.extend(["--output", str(tmp_path / "report.json")])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "Output format must be" in " ".join(result.output.split())
    assert not isinstance(result.exception, AssertionError)


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_invalid_report_format_is_rejected_before_any_scan_work(
    command: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("scan service must not run for an invalid report format")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", unexpected_call)
    monkeypatch.setattr(SecurityWorkflowService, "preview_sweep_details", unexpected_call)
    arguments = [command, str(tmp_path), "--report-format", "summary"]
    if command == "query":
        arguments.extend(["--cwe", "CWE-89"])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "Report format must be json, markdown, sarif, or all" in " ".join(result.output.split())
    assert not isinstance(result.exception, AssertionError)


@pytest.mark.parametrize(
    "extra_arguments",
    [
        ["--output", "reports"],
        ["--report-format", "json"],
    ],
)
def test_no_report_rejects_persisted_report_options_before_scan(
    extra_arguments: list[str],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("scan service must not run for conflicting report options")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", unexpected_call)
    result = runner.invoke(
        app,
        ["query", str(tmp_path), "--cwe", "CWE-89", "--no-report", *extra_arguments],
    )

    assert result.exit_code == 2
    assert "--no-report cannot be combined" in Text.from_ansi(result.output).plain
    assert not isinstance(result.exception, AssertionError)


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_conflicting_output_and_export_are_rejected_before_scan(
    command: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("scan service must not run for conflicting destinations")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", unexpected_call)
    monkeypatch.setattr(SecurityWorkflowService, "preview_sweep_details", unexpected_call)
    destination = tmp_path / "result.tar.gz"
    arguments = [
        command,
        str(tmp_path),
        "--output",
        str(destination),
        "--export",
        str(destination),
    ]
    if command == "query":
        arguments.extend(["--cwe", "CWE-89"])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "must be distinct" in result.output
    assert not isinstance(result.exception, AssertionError)


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_file_output_is_rejected_before_scan(
    command: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("scan service must not run for a directory output")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", unexpected_call)
    monkeypatch.setattr(SecurityWorkflowService, "preview_sweep_details", unexpected_call)
    output_file = tmp_path / "report.json"
    output_file.write_text("existing report", encoding="utf-8")
    arguments = [command, str(tmp_path), "--output", str(output_file)]
    if command == "query":
        arguments.extend(["--cwe", "CWE-89"])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "Report destination must be a directory" in result.output
    assert not isinstance(result.exception, AssertionError)


def test_invalid_cwe_is_rejected_before_runtime_construction(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_build(*_args, **_kwargs):
        raise AssertionError("runtime must not be built for an invalid CWE")

    monkeypatch.setattr(RuntimeFactory, "build", unexpected_build)

    result = runner.invoke(app, ["query", str(tmp_path), "--cwe", "not-a-cwe"])

    assert result.exit_code == 2
    assert "Invalid CWE ID" in result.output
    assert not isinstance(result.exception, AssertionError)


def test_invalid_sensitive_file_opt_in_is_rejected_before_runtime_construction(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_build(*_args, **_kwargs):
        raise AssertionError("runtime must not be built for an invalid sensitive-file opt-in")

    monkeypatch.setattr(RuntimeFactory, "build", unexpected_build)

    result = runner.invoke(
        app,
        [
            "query",
            str(tmp_path),
            "--cwe",
            "CWE-89",
            "--allow-sensitive-file",
            ".env*",
        ],
    )

    assert result.exit_code == 2
    assert "does not allow glob patterns" in result.output
    assert not isinstance(result.exception, AssertionError)
