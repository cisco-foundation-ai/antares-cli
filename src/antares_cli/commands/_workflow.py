# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared command helpers for workflow-backed commands."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Never

import typer
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from antares_cli.config import resolve_data_root
from antares_cli.core.service import WorkflowResult
from antares_cli.inference.backend import InferenceError
from antares_cli.output.renderer import render_finding_card, render_summary_panel
from antares_cli.output.report import (
    REPORT_FORMATS,
    OutputFormat,
    normalize_output_format,
    normalize_report_formats,
    serialize_report_markdown,
    serialize_report_sarif,
    write_report,
    write_report_text,
)
from antares_cli.run_history import (
    InvocationContext,
    export_run_bundle,
    record_failed_run,
    record_workflow_run,
)


def render_workflow_result(console: Console, result: WorkflowResult) -> None:
    console.print(
        render_summary_panel(
            result.summary,
            findings=result.findings,
            checked_cwe_ids=_checked_cwe_ids(result),
            per_cwe_results=result.per_cwe_results,
        )
    )
    for finding in result.findings:
        console.print(render_finding_card(finding))
    _emit_stderr_warnings(result)


def write_workflow_reports(
    *,
    report_directory: Path | None,
    report_formats: tuple[OutputFormat, ...],
    result: WorkflowResult,
) -> Path | None:
    if report_directory is None:
        return None
    private_reports_root = (resolve_data_root() / "reports").resolve(strict=False)
    if report_directory.parent == private_reports_root:
        private_reports_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        private_reports_root.chmod(0o700)
    directory_existed = report_directory.exists()
    report_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not directory_existed:
        report_directory.chmod(0o700)
    for report_format in report_formats:
        output_path = report_directory / _report_filename(report_format)
        if report_format == "json":
            write_report_text(output_path, result.to_json())
        else:
            write_report(
                output_path,
                result.findings,
                result.summary,
                output_format=report_format,
                per_cwe_results=result.per_cwe_results,
                checked_cwe_ids=_checked_cwe_ids(result),
            )
    for omitted_format in set(REPORT_FORMATS) - set(report_formats):
        (report_directory / _report_filename(omitted_format)).unlink(missing_ok=True)
    return report_directory


def workflow_stdout_text(result: WorkflowResult, output_format: str) -> str:
    _emit_stderr_warnings(result)
    normalized_format = normalize_output_format(output_format)
    if normalized_format == "json":
        return result.to_json()
    if normalized_format == "markdown":
        return serialize_report_markdown(
            result.findings,
            result.summary,
            per_cwe_results=result.per_cwe_results,
            checked_cwe_ids=_checked_cwe_ids(result),
        )
    if normalized_format == "sarif":
        return serialize_report_sarif(
            result.findings,
            result.summary,
            per_cwe_results=result.per_cwe_results,
        )
    raise ValueError("Output format is required for stdout serialization.")


def resolve_stdout_format(
    *,
    output_format: str | None,
) -> OutputFormat | None:
    return normalize_output_format(output_format)


def resolve_cli_stdout_format(
    *,
    output_format: str | None,
) -> OutputFormat | None:
    """Validate output configuration and present failures as CLI usage errors."""
    try:
        return resolve_stdout_format(output_format=output_format)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


def resolve_cli_report_formats(
    *,
    requested_formats: tuple[str, ...],
    reports_enabled: bool,
    output: Path | None,
) -> tuple[OutputFormat, ...]:
    """Validate persisted report selection before scan work begins."""
    if not reports_enabled:
        if requested_formats:
            raise typer.BadParameter("--no-report cannot be combined with --report-format")
        if output is not None:
            raise typer.BadParameter("--no-report cannot be combined with --output")
        return ()
    try:
        return normalize_report_formats(requested_formats)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


def resolve_report_directory(
    *,
    output: Path | None,
    execution_id: str,
    reports_enabled: bool,
) -> Path | None:
    """Resolve the explicit or private default directory for shareable reports."""
    if not reports_enabled:
        return None
    if output is not None:
        return output.expanduser().resolve(strict=False)
    return (resolve_data_root() / "reports" / execution_id).resolve(strict=False)


def validate_output_destinations(
    *,
    report_directory: Path | None,
    export_path: Path | None,
) -> None:
    """Reject conflicting or impossible destinations before model work begins."""
    if report_directory is not None:
        if report_directory.exists() and not report_directory.is_dir():
            raise typer.BadParameter(f"Report destination must be a directory: {report_directory}")
        writable_directory = (
            report_directory
            if report_directory.exists()
            else _nearest_existing_parent(report_directory)
        )
        if writable_directory is not None:
            _probe_writable_directory(writable_directory)
    if export_path is not None:
        destination = export_path.expanduser()
        if destination.exists() and destination.is_dir():
            raise typer.BadParameter(f"Export destination is a directory: {destination}")
        existing_parent = _nearest_existing_parent(destination)
        if existing_parent is not None and not existing_parent.is_dir():
            raise typer.BadParameter(
                f"Output destination has a non-directory parent: {existing_parent}"
            )
        if existing_parent is not None:
            _probe_writable_directory(existing_parent)
    if export_path is not None and not export_path.name.lower().endswith(".tar.gz"):
        raise typer.BadParameter("--export must use a .tar.gz filename")
    if report_directory is None or export_path is None:
        return
    resolved_output = report_directory.resolve(strict=False)
    resolved_export = export_path.expanduser().resolve(strict=False)
    if (
        resolved_output == resolved_export
        or resolved_output in resolved_export.parents
        or resolved_export in resolved_output.parents
    ):
        raise typer.BadParameter("--output and --export must be distinct destinations")


def repository_artifact_excludes(
    *,
    target: Path,
    output: Path | None,
    export_path: Path | None,
) -> list[str]:
    """Return in-repository output paths that must not become scan inputs."""
    repository_root = target.expanduser().resolve()
    excludes: list[str] = []
    for destination in (output, export_path):
        if destination is None:
            continue
        resolved_destination = destination.expanduser().resolve(strict=False)
        try:
            relative_destination = resolved_destination.relative_to(repository_root)
        except ValueError:
            continue
        relative_path = relative_destination.as_posix()
        if relative_path and relative_path != "." and relative_path not in excludes:
            excludes.append(relative_path)
    return excludes


def record_workflow_run_best_effort(
    result: WorkflowResult,
    *,
    invocation: InvocationContext,
    target: Path,
    output_path: Path | None = None,
    status: str = "completed",
) -> dict[str, object] | None:
    """Persist private history without allowing it to hide a completed result."""
    try:
        return record_workflow_run(
            result,
            invocation=invocation,
            target=target,
            output_path=output_path,
            status=status,
        )
    except Exception as error:
        _warn_history_failure(error)
        return None


def record_failed_run_best_effort(
    *,
    invocation: InvocationContext,
    mode: str,
    target: Path,
    error: Exception,
    request_metadata: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Persist failure provenance without replacing the original CLI error."""
    try:
        return record_failed_run(
            invocation=invocation,
            mode=mode,
            target=target,
            error=error,
            request_metadata=request_metadata,
        )
    except Exception as persistence_error:
        _warn_history_failure(persistence_error)
        return None


def raise_cli_error(error: Exception) -> Never:
    if isinstance(error, InferenceError):
        stderr_console = Console(stderr=True)
        stderr_console.print(
            f"[bold red]Error:[/bold red] Inference backend failed: {escape(str(error))}"
        )
        raise typer.Exit(code=2) from error
    if isinstance(error, ValueError):
        raise typer.BadParameter(str(error)) from error
    stderr_console = Console(stderr=True)
    stderr_console.print(
        f"[bold red]Error:[/bold red] Scan failed ({type(error).__name__}): {escape(str(error))}"
    )
    raise typer.Exit(code=2) from error


def finalize_and_record_workflow_result(
    result: WorkflowResult,
    *,
    invocation: InvocationContext,
    target: Path,
    report_directory: Path | None,
    report_formats: tuple[OutputFormat, ...],
    stdout_format: str | None,
    console: Console,
    fail_on_findings: bool = False,
    export_path: Path | None = None,
) -> None:
    """Write reports, record private provenance, and apply the requested exit policy."""
    try:
        written = write_workflow_reports(
            report_directory=report_directory,
            report_formats=report_formats,
            result=result,
        )
    except Exception as error:
        _raise_destination_error("reports", error)
    if written is not None:
        report_console = console if stdout_format is None else Console(stderr=True)
        _print_report_location(report_console, written, report_formats)
    has_operational_failures = workflow_result_has_operational_failures(result)
    record = record_workflow_run_best_effort(
        result,
        invocation=invocation,
        target=target,
        output_path=written,
        status="incomplete" if has_operational_failures else "completed",
    )
    if export_path is not None:
        if record is None:
            _raise_destination_error(
                "trace bundle",
                RuntimeError("private run history could not be saved"),
            )
        export_path = export_path.expanduser()
        try:
            export_run_bundle(record, export_path)
        except Exception as error:
            _raise_destination_error("trace bundle", error)
        if stdout_format is None:
            console.print(f"Exported trace bundle → [bold]{escape(str(export_path))}[/bold]")
    if has_operational_failures:
        raise typer.Exit(code=2)
    if fail_on_findings and result.findings:
        raise typer.Exit(code=1)


def workflow_result_has_operational_failures(result: WorkflowResult) -> bool:
    """Return whether a scan ended without evaluating all requested work."""
    return (
        result.summary.generation_errors > 0
        or result.summary.failed_workers > 0
        or result.summary.incomplete_reason is not None
    )


def _emit_stderr_warnings(result: WorkflowResult) -> None:
    """Print warnings to stderr so they're visible even when stdout is piped."""
    warnings = result._collect_warnings()
    for warning in warnings:
        print(f"antares: warning: {warning}", file=sys.stderr)


def _nearest_existing_parent(path: Path) -> Path | None:
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent if parent.exists() else None


def _probe_writable_directory(directory: Path) -> None:
    probe_path: Path | None = None
    try:
        file_descriptor, probe_name = tempfile.mkstemp(
            dir=directory,
            prefix=".antares-write-probe-",
        )
        os.close(file_descriptor)
        probe_path = Path(probe_name)
    except OSError as error:
        raise typer.BadParameter(f"Output directory is not writable: {directory}") from error
    finally:
        if probe_path is not None:
            probe_path.unlink(missing_ok=True)


def _warn_history_failure(error: Exception) -> None:
    print(
        "antares: warning: could not save private run history "
        f"({type(error).__name__}); set ANTARES_DATA_DIR to a writable directory.",
        file=sys.stderr,
    )


def _raise_destination_error(kind: str, error: Exception) -> Never:
    stderr_console = Console(stderr=True)
    stderr_console.print(
        f"[bold red]Error:[/bold red] Could not write {escape(kind)} "
        f"({escape(type(error).__name__)}): {escape(str(error))}"
    )
    raise typer.Exit(code=2) from error


def _report_filename(report_format: OutputFormat) -> str:
    return {
        "json": "report.json",
        "markdown": "report.md",
        "sarif": "report.sarif",
    }[report_format]


def _checked_cwe_ids(result: WorkflowResult) -> list[str]:
    raw_cwe_ids = result.metadata.get("cwe_ids")
    if not isinstance(raw_cwe_ids, list):
        return []
    return [cwe_id for cwe_id in raw_cwe_ids if isinstance(cwe_id, str)]


def _print_report_location(
    console: Console,
    report_directory: Path,
    report_formats: tuple[OutputFormat, ...],
) -> None:
    format_labels = {
        "json": "JSON",
        "markdown": "Markdown",
        "sarif": "SARIF",
    }
    rendered_formats = ", ".join(format_labels[item] for item in report_formats)
    path_text = Text(str(report_directory), style="bold cyan", overflow="fold")
    path_text.stylize(f"link {report_directory.as_uri()}")
    line = Text(f"Reports ({rendered_formats}) → ")
    line.append_text(path_text)
    console.print(line, soft_wrap=True)
