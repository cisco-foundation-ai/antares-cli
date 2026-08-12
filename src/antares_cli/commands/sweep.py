# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Sweep command entry point."""

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from antares_cli.agent.execution_policy import (
    DEFAULT_TERMINAL_CALL_BUDGET,
    MAX_TERMINAL_CALL_BUDGET,
    MIN_TERMINAL_CALL_BUDGET,
)
from antares_cli.commands._interaction import can_interact
from antares_cli.commands._selection_options import parse_cwe_level, parse_scan_scope
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
from antares_cli.core.cwe_selection_limits import (
    DEFAULT_AUTOMATIC_CWE_LIMIT,
    MIN_AUTOMATIC_CWE_LIMIT,
)
from antares_cli.core.cwe_selection_models import CweSelectionPlan
from antares_cli.core.service import (
    SecurityWorkflowService,
    SweepPreview,
    SweepProgressCallback,
    SweepRequest,
    WorkflowResult,
)
from antares_cli.core.worker_limits import DEFAULT_SWEEP_WORKERS, MAX_SWEEP_WORKERS
from antares_cli.run_history import (
    InvocationContext,
    capture_invocation,
)

console = Console()
selection_console = Console(stderr=True)
RunSweepFn = Callable[[SweepProgressCallback | None], WorkflowResult]


@dataclass(frozen=True, slots=True)
class SweepCommandOptions:
    path: Path
    query: str | None
    workers: int
    output: Path | None
    output_format: str | None
    profile: str | None
    backend: str | None
    endpoint: str | None
    model: str | None
    cwe: str | None
    scope: str
    cwe_level: str
    no_tui: bool
    fail_on_findings: bool
    export_path: Path | None
    terminal_call_budget: int | None
    allow_sensitive_files: tuple[str, ...] = ()
    max_cwes: int = DEFAULT_AUTOMATIC_CWE_LIMIT
    reports_enabled: bool = True
    report_formats: tuple[str, ...] = ()


def sweep_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository directory to scan.",
    ),
    query: str | None = typer.Option(
        None,
        "--query",
        "-q",
        help="Additional instructions applied to every CWE investigation.",
    ),
    workers: int = typer.Option(
        DEFAULT_SWEEP_WORKERS,
        "--workers",
        min=1,
        max=MAX_SWEEP_WORKERS,
        help=f"Concurrent sweep workers (maximum {MAX_SWEEP_WORKERS}).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Directory for report artifacts. Defaults to the private Antares data directory.",
    ),
    output_format: str | None = typer.Option(
        None,
        "--format",
        help=("Serialize json, markdown, or sarif to stdout and disable the TUI."),
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
    backend: str | None = typer.Option(None, "--backend", help="Inference backend (remote)."),
    endpoint: str | None = typer.Option(None, "--endpoint", help="Remote inference endpoint URL."),
    model: str | None = typer.Option(
        None, "--model", envvar="ANTARES_MODEL", help="Model name or ID."
    ),
    cwe: str | None = typer.Option(
        None,
        "--cwe",
        help="Comma-separated CWE IDs. Omit to use repo-aware auto selection.",
    ),
    scope: str = typer.Option(
        "auto",
        "--scope",
        help="Automatic candidate set: auto, top25, or owasp.",
    ),
    cwe_level: str = typer.Option(
        "all",
        "--cwe-level",
        help="MITRE CWE abstraction level for auto selection: all, pillar, class, base, variant, or compound.",
    ),
    max_cwes: int = typer.Option(
        DEFAULT_AUTOMATIC_CWE_LIMIT,
        "--max-cwes",
        min=MIN_AUTOMATIC_CWE_LIMIT,
        help="Maximum ranked CWE targets selected automatically; ignored with --cwe.",
    ),
    no_tui: bool = typer.Option(
        False,
        "--no-tui",
        help="Disable the interactive TUI and use stdout/file output only.",
    ),
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
        help=(
            "Repository tool-call budget per CWE worker. Appends a countdown to each response "
            "and switches to submission-only retries when exhausted."
        ),
    ),
    allow_sensitive_file: list[str] | None = typer.Option(
        None,
        "--allow-sensitive-file",
        help=("Allow one exact repository-relative sensitive file; repeat for additional files."),
    ),
) -> None:
    """Scan a repository across explicit or automatically selected CWE IDs."""
    options = SweepCommandOptions(
        path=path,
        query=query,
        workers=workers,
        output=output,
        output_format=output_format,
        profile=profile,
        backend=backend,
        endpoint=endpoint,
        model=model,
        cwe=cwe,
        scope=scope,
        cwe_level=cwe_level,
        no_tui=no_tui,
        fail_on_findings=fail_on_findings,
        export_path=export,
        terminal_call_budget=tool_budget,
        allow_sensitive_files=tuple(allow_sensitive_file or ()),
        max_cwes=max_cwes,
        reports_enabled=not no_report,
        report_formats=tuple(report_format or ()),
    )
    _run_sweep_command(options)


def _run_sweep_command(
    options: SweepCommandOptions,
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
    stdout_format = resolve_cli_stdout_format(
        output_format=options.output_format,
    )
    request = _build_sweep_request(options, report_directory=report_directory)
    service = SecurityWorkflowService()
    preview = _preview_sweep(service, request, options, invocation)
    worker_labels = [worker.label for worker in preview.workers]
    for line in _selection_preview_lines(preview.selection_plan, request):
        selection_console.print(line, markup=False)
    result, used_tui = _run_sweep_interactively_or_headless(
        options,
        request,
        invocation,
        service,
        preview.selection_plan,
        worker_labels,
        stdout_format,
    )
    _render_sweep_result(
        options,
        result,
        stdout_format,
        used_tui=used_tui,
    )
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


def _build_sweep_request(
    options: SweepCommandOptions,
    *,
    report_directory: Path | None,
) -> SweepRequest:
    return SweepRequest(
        target=options.path,
        query=options.query,
        cwe_ids=parse_cwe_id_list(options.cwe),
        workers=options.workers,
        profile=options.profile,
        backend=options.backend,
        endpoint=options.endpoint,
        model=options.model,
        scope=parse_scan_scope(options.scope),
        cwe_level=parse_cwe_level(options.cwe_level),
        max_cwes=options.max_cwes,
        terminal_call_budget=options.terminal_call_budget,
        additional_ignore_paths=repository_artifact_excludes(
            target=options.path,
            output=report_directory,
            export_path=options.export_path,
        ),
        allow_sensitive_files=list(options.allow_sensitive_files),
    )


def _preview_sweep(
    service: SecurityWorkflowService,
    request: SweepRequest,
    options: SweepCommandOptions,
    invocation: InvocationContext,
) -> SweepPreview:
    try:
        return service.preview_sweep_details(request)
    except Exception as error:
        _record_failed_sweep(invocation, request, options, error)
        raise_cli_error(error)


def _selection_preview_lines(
    selection_plan: CweSelectionPlan,
    request: SweepRequest,
) -> tuple[str, ...]:
    selected_ids = selection_plan.cwe_ids()
    if selection_plan.intent.mode == "explicit":
        selection_summary = (
            f"Exact selection: {len(selected_ids)} user-requested CWE targets (uncapped)."
        )
    else:
        omitted_count = max(0, selection_plan.candidate_cwe_count - len(selected_ids))
        selection_summary = (
            f"Automatic selection: {len(selected_ids)} of "
            f"{selection_plan.candidate_cwe_count} eligible CWE candidates "
            f"(limit {selection_plan.automatic_limit}; {omitted_count} omitted)."
        )
    plan_argv = ["antares", "plan", str(request.target)]
    if request.cwe_ids:
        plan_argv.extend(("--cwe", ",".join(request.cwe_ids)))
    else:
        plan_argv.extend(
            (
                "--scope",
                request.scope,
                "--cwe-level",
                request.cwe_level,
                "--max-cwes",
                str(request.max_cwes),
            )
        )
    lines = [selection_summary]
    if selection_plan.priority_baseline_name is not None:
        lines.append(
            f"Priority baseline: {selection_plan.priority_baseline_selected_count} of "
            f"{selection_plan.priority_baseline_eligible_count} eligible "
            f"{selection_plan.priority_baseline_name} entries selected."
        )
    tier_counts = selection_plan.to_dict()["selection_tier_counts"]
    if isinstance(tier_counts, dict) and tier_counts:
        tier_summary = ", ".join(
            f"{tier_counts[tier]} {tier}"
            for tier in ("repository-specific", "priority-baseline", "ranked-fill")
            if tier in tier_counts
        )
        lines.append(f"Portfolio: {tier_summary}.")
    lines.extend(
        (
            f"Policy: {selection_plan.selection_policy}",
            f"Selected CWEs: {', '.join(selected_ids)}",
            f"Full rationale: {shlex.join(plan_argv)}",
        )
    )
    return tuple(lines)


def _run_sweep_interactively_or_headless(
    options: SweepCommandOptions,
    request: SweepRequest,
    invocation: InvocationContext,
    service: SecurityWorkflowService,
    selection_plan: CweSelectionPlan,
    worker_labels: list[str],
    stdout_format: str | None,
) -> tuple[WorkflowResult, bool]:
    run_sweep = _build_run_sweep_callback(service, request, selection_plan)
    use_tui = can_interact() and not options.no_tui and stdout_format is None
    if use_tui:
        return _run_sweep_tui(
            options,
            request,
            invocation,
            worker_labels,
            run_sweep,
        ), True
    return (
        _run_sweep_headless(
            options,
            request,
            invocation,
            run_sweep,
        ),
        False,
    )


def _build_run_sweep_callback(
    service: SecurityWorkflowService,
    request: SweepRequest,
    selection_plan: CweSelectionPlan,
) -> RunSweepFn:
    def run_sweep(progress_callback: SweepProgressCallback | None = None) -> WorkflowResult:
        return service.run_cwe_sweep(
            request,
            progress_callback=progress_callback,
            selection_plan=selection_plan,
        )

    return run_sweep


def _run_sweep_tui(
    options: SweepCommandOptions,
    request: SweepRequest,
    invocation: InvocationContext,
    worker_labels: list[str],
    run_sweep: RunSweepFn,
) -> WorkflowResult:
    from antares_cli.tui.app import AntaresApp
    from antares_cli.tui.runner import SweepRunner
    from antares_cli.tui.screens.sweep import SweepOverviewScreen, WorkerDetailScreen

    sweep_runner: SweepRunner | None = None

    def start_sweep() -> None:
        nonlocal sweep_runner
        screen = tui_app.screen
        if isinstance(screen, SweepOverviewScreen):
            screen.worker_list.set_workers(worker_labels)
            screen.findings.set_workspace_root(str(options.path))
        sweep_runner = SweepRunner(
            app=tui_app,
            run_sweep=run_sweep,
            target_path=options.path,
            worker_labels=worker_labels,
        )
        sweep_runner.start()

    def on_drill_in(detail_screen: WorkerDetailScreen) -> None:
        if sweep_runner is not None:
            sweep_runner.replay_into_detail_screen(detail_screen)

    profile_display_name = options.profile or options.model or options.backend or "auto"
    tui_app = AntaresApp(
        profile=profile_display_name,
        target=str(options.path.resolve()),
        sweep_label=_sweep_label(options),
        worker_count=len(worker_labels),
        on_ready=start_sweep,
        on_drill_in=on_drill_in,
    )
    tui_app.run()
    if sweep_runner is None:
        error = RuntimeError("Interactive sweep closed before it started.")
        _record_failed_sweep(invocation, request, options, error)
        raise_cli_error(error)
    if sweep_runner.error is not None:
        _record_failed_sweep(invocation, request, options, sweep_runner.error)
        raise_cli_error(sweep_runner.error)
    tui_result = sweep_runner.result
    if tui_result is None:
        error = RuntimeError("Interactive sweep ended before all work completed.")
        _record_failed_sweep(invocation, request, options, error)
        raise_cli_error(error)
    return tui_result


def _run_sweep_headless(
    options: SweepCommandOptions,
    request: SweepRequest,
    invocation: InvocationContext,
    run_sweep: RunSweepFn,
) -> WorkflowResult:
    try:
        result = run_sweep(None)
    except Exception as error:
        # Inference backends can raise arbitrary exceptions; catch broadly so we can
        # record the failure and surface a clean CLI error instead of a traceback.
        _record_failed_sweep(invocation, request, options, error)
        raise_cli_error(error)
    return result


def _render_sweep_result(
    options: SweepCommandOptions,
    result: WorkflowResult,
    stdout_format: str | None,
    *,
    used_tui: bool,
) -> None:
    if stdout_format is not None:
        print(workflow_stdout_text(result, stdout_format))
        return
    if not used_tui:
        console.print(
            f"[bold cyan]antares sweep[/bold cyan] {escape(_sweep_label(options))} sweep with "
            f"[bold]{options.workers}[/bold] workers against "
            f"[bold]{escape(str(options.path))}[/bold]",
        )
        render_workflow_result(console, result)


def _record_failed_sweep(
    invocation: InvocationContext,
    request: SweepRequest,
    options: SweepCommandOptions,
    error: Exception,
) -> None:
    record_failed_run_best_effort(
        invocation=invocation,
        mode="cwe_sweep",
        target=options.path,
        error=error,
        request_metadata={
            "query": request.query,
            "cwe_ids": request.cwe_ids,
            "scope": request.scope,
            "cwe_level": request.cwe_level,
            "max_cwes": request.max_cwes,
            "model": options.model,
            "backend": options.backend,
            "profile": options.profile,
            "allowed_sensitive_files": request.allow_sensitive_files,
        },
    )


def _sweep_label(options: SweepCommandOptions) -> str:
    if options.cwe:
        return "CWE"
    return f"{parse_scan_scope(options.scope)}/{options.cwe_level}"
