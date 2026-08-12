# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Machine-friendly query command."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

from antares_cli.agent.execution_policy import (
    DEFAULT_TERMINAL_CALL_BUDGET,
    MAX_TERMINAL_CALL_BUDGET,
    MIN_TERMINAL_CALL_BUDGET,
)
from antares_cli.commands._workflow import (
    finalize_and_record_workflow_result,
    raise_cli_error,
    record_failed_run_best_effort,
    render_workflow_result,
    repository_artifact_excludes,
    resolve_cli_report_formats,
    resolve_cli_stdout_format,
    resolve_report_directory,
    validate_output_destinations,
    workflow_stdout_text,
)
from antares_cli.core.cwe import parse_cwe_id_list
from antares_cli.core.service import QueryRequest, SecurityWorkflowService, WorkflowResult
from antares_cli.run_history import (
    InvocationContext,
    capture_invocation,
)

console = Console()


@dataclass(frozen=True, slots=True)
class QueryCommandOptions:
    path: Path
    cwe: str
    query: str | None
    output: Path | None
    output_format: str | None
    profile: str | None
    model: str | None
    backend: str | None
    endpoint: str | None
    fail_on_findings: bool
    export_path: Path | None
    terminal_call_budget: int | None
    allow_sensitive_files: tuple[str, ...] = ()
    reports_enabled: bool = True
    report_formats: tuple[str, ...] = ()


def query_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository directory to scan.",
    ),
    cwe: str = typer.Option(..., "--cwe", help="Required comma-separated CWE IDs."),
    query: str | None = typer.Option(
        None,
        "--query",
        "-q",
        help="Additional CWE-scoped security instructions.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Directory for report artifacts. Defaults to the private Antares data directory.",
    ),
    output_format: str | None = typer.Option(
        None,
        "--format",
        help="Serialize json, markdown, or sarif to stdout instead of rich terminal output.",
    ),
    report_format: list[str] | None = typer.Option(
        None,
        "--report-format",
        help=("Persist json, markdown, sarif, or all; repeat to select multiple. Default: all."),
    ),
    no_report: bool = typer.Option(
        False,
        "--no-report",
        help="Do not persist JSON, Markdown, or SARIF report artifacts.",
    ),
    profile: str | None = typer.Option(None, "--profile", "-p", help="Connection profile name."),
    model: str | None = typer.Option(
        None, "--model", envvar="ANTARES_MODEL", help="Override the configured Antares model."
    ),
    backend: str | None = typer.Option(None, "--backend", help="Inference backend (remote)."),
    endpoint: str | None = typer.Option(None, "--endpoint", help="Remote inference endpoint URL."),
    fail_on_findings: bool = typer.Option(
        False,
        "--fail-on-findings",
        help="Exit 1 when any findings exist.",
    ),
    export: Path | None = typer.Option(
        None,
        "--export",
        help=(
            "Write a content-redacted trace bundle (.tar.gz). "
            "Inspect retained metadata before sharing."
        ),
    ),
    tool_budget: int = typer.Option(
        DEFAULT_TERMINAL_CALL_BUDGET,
        "--tool-budget",
        min=MIN_TERMINAL_CALL_BUDGET,
        max=MAX_TERMINAL_CALL_BUDGET,
        help="Repository tool-call budget; switches to submission-only retries when exhausted.",
    ),
    allow_sensitive_file: list[str] | None = typer.Option(
        None,
        "--allow-sensitive-file",
        help=("Allow one exact repository-relative sensitive file; repeat for additional files."),
    ),
) -> None:
    """Scan a repository for one or more explicit CWE IDs."""
    options = QueryCommandOptions(
        path=path,
        cwe=cwe,
        query=query,
        output=output,
        output_format=output_format,
        profile=profile,
        model=model,
        backend=backend,
        endpoint=endpoint,
        fail_on_findings=fail_on_findings,
        export_path=export,
        terminal_call_budget=tool_budget,
        allow_sensitive_files=tuple(allow_sensitive_file or ()),
        reports_enabled=not no_report,
        report_formats=tuple(report_format or ()),
    )
    _run_query_command(options)


def _run_query_command(
    options: QueryCommandOptions,
    invocation: InvocationContext | None = None,
) -> None:
    invocation = invocation or capture_invocation()
    report_formats = resolve_cli_report_formats(
        requested_formats=options.report_formats,
        reports_enabled=options.reports_enabled,
        output=options.output,
    )
    report_directory = resolve_report_directory(
        output=options.output,
        execution_id=invocation.execution_id,
        reports_enabled=options.reports_enabled,
    )
    validate_output_destinations(
        report_directory=report_directory,
        export_path=options.export_path,
    )
    cwe_ids = _parse_required_cwe_ids(options.cwe)
    stdout_format = resolve_cli_stdout_format(
        output_format=options.output_format,
    )
    request = _build_query_request(options, cwe_ids, report_directory=report_directory)
    result = _run_query_workflow(request, options, invocation)
    _render_query_result(result, stdout_format)
    finalize_and_record_workflow_result(
        result,
        invocation=invocation,
        target=options.path,
        report_directory=report_directory,
        report_formats=report_formats,
        stdout_format=stdout_format,
        console=console,
        fail_on_findings=options.fail_on_findings,
        export_path=options.export_path,
    )


def _parse_required_cwe_ids(raw_cwe_ids: str) -> list[str]:
    cwe_ids = parse_cwe_id_list(raw_cwe_ids)
    if not cwe_ids:
        raise typer.BadParameter("query requires at least one CWE ID via --cwe.")
    return cwe_ids


def _build_query_request(
    options: QueryCommandOptions,
    cwe_ids: list[str],
    *,
    report_directory: Path | None,
) -> QueryRequest:
    return QueryRequest(
        target=options.path,
        query=options.query,
        cwe_ids=cwe_ids,
        profile=options.profile,
        model=options.model,
        backend=options.backend,
        endpoint=options.endpoint,
        api_key=None,
        terminal_call_budget=options.terminal_call_budget,
        additional_ignore_paths=repository_artifact_excludes(
            target=options.path,
            output=report_directory,
            export_path=options.export_path,
        ),
        allow_sensitive_files=list(options.allow_sensitive_files),
    )


def _run_query_workflow(
    request: QueryRequest,
    options: QueryCommandOptions,
    invocation: InvocationContext,
) -> WorkflowResult:
    try:
        return SecurityWorkflowService().run_query(request)
    except Exception as error:
        record_failed_run_best_effort(
            invocation=invocation,
            mode="query",
            target=options.path,
            error=error,
            request_metadata={
                "query": options.query,
                "cwe_ids": request.cwe_ids,
                "model": options.model,
                "backend": options.backend,
                "profile": options.profile,
                "allowed_sensitive_files": request.allow_sensitive_files,
            },
        )
        raise_cli_error(error)


def _render_query_result(result: WorkflowResult, stdout_format: str | None) -> None:
    if stdout_format is not None:
        print(workflow_stdout_text(result, stdout_format))
    else:
        render_workflow_result(console, result)
