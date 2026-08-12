# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run history inspection commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Never

import typer
from rich.console import Console
from rich.markup import escape

from antares_cli.output.renderer import render_key_value_panel
from antares_cli.run_history import (
    export_run_bundle,
    export_run_bundles,
    find_run_record,
    load_run_records,
    resolve_investigation_trace,
    runs_index_path,
)

runs_app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Review recorded Antares runs and investigation traces.",
)
console = Console()


@runs_app.command("list")
def list_runs_command(
    limit: int = typer.Option(20, "--limit", "-n", min=1, help="Maximum runs to show."),
    last: int | None = typer.Option(
        None, "--last", min=1, help="Show only the N most recent runs."
    ),
    json_output: bool = typer.Option(False, "--json", help="Print run records as JSON."),
) -> None:
    """List recent locally recorded scans."""
    effective_limit = last if last is not None else limit
    try:
        records = load_run_records(limit=effective_limit)
    except Exception as error:
        _raise_history_error("read run history", error)
    if json_output:
        print(json.dumps(records, indent=2, sort_keys=True))
        return
    if not records:
        console.print(
            f"No Antares runs recorded yet. History index: {runs_index_path()}", markup=False
        )
        return

    for record in records:
        target_git = _dict_value(record, "target_git")
        invocation = _dict_value(record, "invocation")
        commit = str(target_git.get("commit") or "")
        investigation_traces = _investigation_traces(record)
        command = str(invocation.get("command") or "")
        console.print(
            render_key_value_panel(
                "RUN",
                [
                    ("Started", invocation.get("started_at") or ""),
                    ("ID", record.get("execution_id") or ""),
                    ("Status", record.get("status") or ""),
                    ("Mode", record.get("mode") or ""),
                    ("Target", record.get("target") or ""),
                    ("Command", command),
                    ("Commit", commit),
                    ("Investigations", len(investigation_traces)),
                ],
            )
        )


@runs_app.command("show")
def show_run_command(
    run_id: str = typer.Argument(..., help="Execution id or unique prefix."),
    json_output: bool = typer.Option(
        True, "--json/--summary", help="Print full JSON or compact summary."
    ),
) -> None:
    """Show one recorded scan and its provenance."""
    record = _find_run_or_exit(run_id)
    if json_output:
        print(json.dumps(record, indent=2, sort_keys=True))
        return

    target_git = _dict_value(record, "target_git")
    invocation = _dict_value(record, "invocation")
    investigation_traces = _investigation_traces(record)
    console.print(f"Run: {record.get('execution_id')}", markup=False)
    console.print(f"Status: {record.get('status')}", markup=False)
    console.print(f"Started: {invocation.get('started_at')}", markup=False)
    console.print(f"Command: {invocation.get('command')}", markup=False)
    console.print(f"Target: {record.get('target')}", markup=False)
    console.print(f"Commit: {target_git.get('commit')}", markup=False)
    console.print(f"Branch: {target_git.get('branch')}", markup=False)
    console.print(f"Investigation traces: {len(investigation_traces)}", markup=False)
    for investigation_trace in investigation_traces:
        console.print(f"- {investigation_trace}", markup=False)


@runs_app.command("trace")
def trace_run_command(
    run_id: str = typer.Argument(..., help="Execution id or unique prefix."),
    cat: bool = typer.Option(False, "--cat", help="Print investigation JSONL contents."),
) -> None:
    """List or print the private investigation traces for one scan."""
    record = _find_run_or_exit(run_id)
    investigation_traces = _investigation_traces(record)
    if not investigation_traces:
        console.print(
            f"Run {record.get('execution_id')} has no investigation traces.", markup=False
        )
        return
    if not cat:
        for investigation_trace in investigation_traces:
            print(investigation_trace)
        return

    for index, investigation_trace in enumerate(investigation_traces):
        try:
            path = resolve_investigation_trace(investigation_trace)
        except ValueError as error:
            raise typer.BadParameter(str(error)) from error
        if len(investigation_traces) > 1:
            print(f"--- {path} ---")
        try:
            with path.open(encoding="utf-8") as trace_file:
                for chunk in iter(lambda: trace_file.read(64 * 1024), ""):
                    sys.stdout.write(chunk)
        except OSError as error:
            _raise_history_error("read investigation trace", error)
        if index != len(investigation_traces) - 1:
            print()


@runs_app.command("export")
def export_runs_command(
    run_ids: list[str] = typer.Argument(
        default=None, help="Execution id(s) or unique prefixes. Omit to export the most recent run."
    ),
    last: int | None = typer.Option(None, "--last", min=1, help="Export the N most recent runs."),
    all_runs: bool = typer.Option(False, "--all", help="Export every recorded run."),
    output: Path | None = typer.Option(
        None, "--output", help="Output path (for a single run) or directory (for multiple runs)."
    ),
) -> None:
    """Export content-redacted trace bundles for selected scans."""
    selector_count = int(bool(run_ids)) + int(last is not None) + int(all_runs)
    if selector_count > 1:
        raise typer.BadParameter("Choose exactly one run selector: run IDs, --last, or --all.")
    try:
        records = _resolve_export_records(run_ids, last=last, all_runs=all_runs)
    except typer.BadParameter:
        raise
    except Exception as error:
        _raise_history_error("read run history", error)
    if not records:
        console.print("No runs found to export.")
        raise typer.Exit(code=1)
    if len(records) == 1:
        record = records[0]
        execution_id = str(record.get("execution_id", "run"))
        output_path = (output or Path(f"{execution_id}.tar.gz")).expanduser()
        _validate_single_export_path(output_path)
        try:
            export_run_bundle(record, output_path)
        except Exception as error:
            _raise_history_error("export run bundle", error)
        investigation_traces = _investigation_traces(record)
        size_bytes = output_path.stat().st_size if output_path.exists() else 0
        size_display = (
            f"{size_bytes / 1024:.1f} KB"
            if size_bytes < 1024 * 1024
            else f"{size_bytes / (1024 * 1024):.1f} MB"
        )
        console.print(
            f"Exported [bold]{escape(execution_id)}[/bold] → "
            f"[bold]{escape(str(output_path))}[/bold] "
            f"({len(investigation_traces)} investigation trace(s), {size_display})"
        )
    else:
        output = output.expanduser() if output is not None else None
        output_suffixes = tuple(suffix.lower() for suffix in output.suffixes[-2:]) if output else ()
        if output is not None and output_suffixes == (".tar", ".gz") and not output.is_dir():
            raise typer.BadParameter(
                f"--output must be a directory when exporting multiple runs, not '{output}'. "
                "Each run is written as <id>.tar.gz inside the directory."
            )
        output_dir = output or Path.cwd()
        if output_dir.exists() and not output_dir.is_dir():
            raise typer.BadParameter(f"--output must be a directory: {output_dir}")
        try:
            exported = export_run_bundles(records, output_dir)
        except Exception as error:
            _raise_history_error("export run bundles", error)
        for record, bundle_path in zip(records, exported, strict=True):
            execution_id = str(record.get("execution_id", "run"))
            investigation_traces = _investigation_traces(record)
            size_bytes = bundle_path.stat().st_size if bundle_path.exists() else 0
            size_display = (
                f"{size_bytes / 1024:.1f} KB"
                if size_bytes < 1024 * 1024
                else f"{size_bytes / (1024 * 1024):.1f} MB"
            )
            console.print(
                f"Exported [bold]{escape(execution_id)}[/bold] → "
                f"[bold]{escape(str(bundle_path))}[/bold] "
                f"({len(investigation_traces)} investigation trace(s), {size_display})"
            )


def _resolve_export_records(
    run_ids: list[str] | None,
    *,
    last: int | None,
    all_runs: bool,
) -> list[dict[str, object]]:
    if all_runs:
        return load_run_records()
    if last is not None:
        return load_run_records(limit=last)
    if run_ids:
        records = load_run_records()
        return [_find_run_in_records(run_id, records) for run_id in run_ids]
    recent = load_run_records(limit=1)
    if not recent:
        raise typer.BadParameter("No runs recorded yet.")
    return recent


def _validate_single_export_path(output_path: Path) -> None:
    if not output_path.name.lower().endswith(".tar.gz"):
        raise typer.BadParameter("--output must use a .tar.gz filename for a single run")
    if output_path.exists() and output_path.is_dir():
        raise typer.BadParameter(f"--output is a directory: {output_path}")
    parent = output_path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if parent.exists() and not parent.is_dir():
        raise typer.BadParameter(f"--output has a non-directory parent: {parent}")


def _raise_history_error(action: str, error: Exception) -> Never:
    error_console = Console(stderr=True)
    error_console.print(
        f"[bold red]Error:[/bold red] Could not {escape(action)} "
        f"({escape(type(error).__name__)}): {escape(str(error))}"
    )
    raise typer.Exit(code=2) from error


def _find_run_or_exit(run_id: str) -> dict[str, object]:
    try:
        return find_run_record(run_id)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    except Exception as error:
        _raise_history_error("read run history", error)


def _find_run_in_records(
    run_id: str,
    records: list[dict[str, object]],
) -> dict[str, object]:
    matches = [
        record for record in records if str(record.get("execution_id", "")).startswith(run_id)
    ]
    if not matches:
        raise typer.BadParameter(f"No Antares run found for id prefix: {run_id}")
    if len(matches) > 1:
        matching_ids = ", ".join(str(record.get("execution_id")) for record in matches[:5])
        raise typer.BadParameter(f"Run id prefix is ambiguous: {matching_ids}")
    return matches[0]


def _dict_value(record: dict[str, object], key: str) -> dict[str, Any]:
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _list_value(record: dict[str, object], key: str) -> list[object]:
    value = record.get(key)
    return value if isinstance(value, list) else []


def _investigation_traces(record: dict[str, object]) -> list[object]:
    traces = _list_value(record, "investigation_traces")
    if traces:
        return traces
    return _list_value(record, "trace_files")
