# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Interactive wizard — launched when user runs `antares` with no arguments."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from prompt_toolkit import prompt
from prompt_toolkit.application import Application
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from rich.console import Console
from rich.markup import escape

from antares_cli.agent.execution_policy import (
    DEFAULT_TERMINAL_CALL_BUDGET,
    resolve_terminal_call_budget,
)
from antares_cli.commands.directory_browser import DirectoryBrowser
from antares_cli.core.cwe_selection_limits import (
    DEFAULT_AUTOMATIC_CWE_LIMIT,
    resolve_automatic_cwe_limit,
)
from antares_cli.core.worker_limits import (
    DEFAULT_SWEEP_WORKERS,
    MAX_SWEEP_WORKERS,
    resolve_sweep_worker_count,
)
from antares_cli.inference.profiles import (
    InferenceProfile,
    ProfileConfigurationError,
    load_profiles,
)
from antares_cli.run_history import capture_invocation

console = Console()


@dataclass
class WizardResult:
    target: Path
    mode: str
    focus: str
    profile_name: str
    output_path: Path | None
    output_format: str | None
    workers: int
    max_cwes: int = DEFAULT_AUTOMATIC_CWE_LIMIT
    terminal_call_budget: int = DEFAULT_TERMINAL_CALL_BUDGET
    cwe: str | None = None
    reports_enabled: bool = True


def _select_from_list(label: str, options: list[str], default_index: int = 0) -> int:
    """Arrow-key navigable selection list. Returns chosen index."""
    selected = [default_index]

    bindings = KeyBindings()

    @bindings.add("up")
    @bindings.add("k")
    def _move_up(event: Any) -> None:
        selected[0] = (selected[0] - 1) % len(options)

    @bindings.add("down")
    @bindings.add("j")
    def _move_down(event: Any) -> None:
        selected[0] = (selected[0] + 1) % len(options)

    @bindings.add("enter")
    def _confirm(event: Any) -> None:
        event.app.exit(result=selected[0])

    @bindings.add("c-c")
    @bindings.add("q")
    def _cancel(event: Any) -> None:
        event.app.exit(result=None)

    def _get_formatted_text() -> FormattedText:
        lines: list[tuple[str, str]] = []
        lines.append(("bold", f"  {label}\n"))
        for i, option in enumerate(options):
            if i == selected[0]:
                lines.append(("ansibrightcyan", f"  ❯ {option}\n"))
            else:
                lines.append(("", f"    {option}\n"))
        lines.append(("ansigray", "\n  ↑↓ navigate · enter confirm"))
        return FormattedText(lines)

    control = FormattedTextControl(_get_formatted_text)
    layout = Layout(Window(content=control, always_hide_cursor=True, wrap_lines=True))

    app: Application[int | None] = Application(
        layout=layout,
        key_bindings=bindings,
        full_screen=False,
    )
    result = app.run()
    if result is None:
        raise KeyboardInterrupt
    return result


def _browse_directory(start: Path | None = None) -> Path | None:
    """Interactive directory browser with fuzzy filtering."""
    return DirectoryBrowser(start).run()


def _confirm_launch(summary_lines: list[tuple[str, str]]) -> bool:
    """Show a styled summary and let user confirm with enter or cancel with escape."""
    selected = [0]  # 0 = Launch, 1 = Cancel

    bindings = KeyBindings()

    @bindings.add("enter")
    def _confirm(event: Any) -> None:
        event.app.exit(result=(selected[0] == 0))

    @bindings.add("left")
    @bindings.add("right")
    @bindings.add("tab")
    @bindings.add("h")
    @bindings.add("l")
    def _toggle(event: Any) -> None:
        selected[0] = 1 - selected[0]

    @bindings.add("c-c")
    @bindings.add("escape")
    def _cancel(event: Any) -> None:
        event.app.exit(result=False)

    def _get_formatted_text() -> FormattedText:
        lines: list[tuple[str, str]] = []
        lines.append(("bold", "\n  Ready to launch\n"))
        lines.append(("ansigray", "  ─────────────────────────────────────────\n"))
        max_label_len = max(len(label) for label, _ in summary_lines)
        for label, value in summary_lines:
            padded_label = label.ljust(max_label_len)
            lines.append(("bold", f"  {padded_label}  "))
            lines.append(("", f"{value}\n"))
        lines.append(("ansigray", "  ─────────────────────────────────────────\n\n"))

        if selected[0] == 0:
            lines.append(("ansibrightgreen bold", "  ▸ Launch "))
            lines.append(("ansigray", "    Cancel"))
        else:
            lines.append(("ansigray", "    Launch "))
            lines.append(("ansired bold", "  ▸ Cancel"))

        lines.append(("ansigray", "\n\n  ←→ toggle · enter confirm"))
        return FormattedText(lines)

    control = FormattedTextControl(_get_formatted_text)
    layout = Layout(Window(content=control, always_hide_cursor=True, wrap_lines=True))

    app: Application[bool] = Application(
        layout=layout,
        key_bindings=bindings,
        full_screen=False,
    )
    return app.run()


def run_wizard() -> WizardResult | None:
    """Run the interactive setup wizard. Returns None if user cancels."""
    console.print("\n[bold cyan]  antares[/bold cyan] — interactive setup\n")
    target = _select_target()
    if target is None:
        return None
    mode = _select_mode()
    cwe, focus = _prompt_cwe_and_focus(mode)
    max_cwes = _prompt_automatic_cwe_limit(mode, cwe)
    workers = _prompt_worker_count(mode, cwe)
    terminal_call_budget = _prompt_tool_budget()
    selected_profile = _select_profile()
    output_path, reports_enabled = _select_output(mode)
    result = WizardResult(
        target=target,
        mode=mode,
        focus=focus,
        profile_name=selected_profile.name,
        output_path=output_path,
        output_format=None,
        workers=workers,
        max_cwes=max_cwes,
        terminal_call_budget=terminal_call_budget,
        cwe=cwe,
        reports_enabled=reports_enabled,
    )
    if not _confirm_wizard_result(result, selected_profile.display):
        return None
    return result


def _select_target() -> Path | None:
    """Browse the local filesystem for a target directory."""
    target = _browse_directory()
    if target is None:
        console.print("  [dim]Cancelled.[/dim]")
        return None
    console.print(f"  [dim]Target:[/dim] {escape(str(target))}\n")
    return target


def _select_mode() -> str:
    mode_index = _select_from_list(
        "Mode",
        [
            "query  — single CWE-scoped scan",
            "sweep  — parallel CWE sweep",
        ],
    )
    return "query" if mode_index == 0 else "sweep"


def _prompt_cwe_and_focus(mode: str) -> tuple[str, str]:
    while True:
        cwe = prompt("  CWE IDs [auto]: ").strip()
        if not cwe or cwe.lower() == "auto":
            cwe = ""
        if mode != "query" or cwe:
            break
        console.print("  [red]query mode requires at least one CWE ID.[/red]")
    focus = prompt("  Additional instructions (blank for CWE default): ").strip()
    return cwe, focus


def _prompt_worker_count(mode: str, cwe: str) -> int:
    if mode != "sweep":
        return 1
    default_workers = min(
        MAX_SWEEP_WORKERS,
        len([part for part in cwe.split(",") if part.strip()]) or DEFAULT_SWEEP_WORKERS,
    )
    while True:
        raw_workers = prompt(f"  Workers [{default_workers}]: ").strip()
        try:
            return resolve_sweep_worker_count(int(raw_workers) if raw_workers else default_workers)
        except ValueError as error:
            console.print(f"  [red]{escape(str(error))}[/red]")


def _prompt_automatic_cwe_limit(mode: str, cwe: str) -> int:
    if mode != "sweep" or cwe:
        return DEFAULT_AUTOMATIC_CWE_LIMIT
    while True:
        raw_limit = prompt(
            f"  Maximum automatic CWE targets [{DEFAULT_AUTOMATIC_CWE_LIMIT}]: "
        ).strip()
        if not raw_limit:
            return DEFAULT_AUTOMATIC_CWE_LIMIT
        try:
            parsed_limit = int(raw_limit)
        except ValueError:
            console.print("  [red]Automatic CWE limit must be an integer.[/red]")
            continue
        try:
            return resolve_automatic_cwe_limit(parsed_limit)
        except ValueError as error:
            console.print(f"  [red]{escape(str(error))}[/red]")


def _prompt_tool_budget() -> int:
    while True:
        raw_budget = prompt(
            f"  Repository tool-call budget [{DEFAULT_TERMINAL_CALL_BUDGET}]: "
        ).strip()
        if not raw_budget:
            return DEFAULT_TERMINAL_CALL_BUDGET
        try:
            parsed_budget = int(raw_budget)
        except ValueError:
            console.print("  [red]Terminal call budget must be an integer.[/red]")
            continue
        try:
            return resolve_terminal_call_budget(parsed_budget)
        except ValueError as error:
            console.print(f"  [red]{escape(str(error))}[/red]")


def _select_profile() -> InferenceProfile:
    try:
        profiles = load_profiles()
    except ProfileConfigurationError as error:
        console.print(f"[red]Invalid inference configuration:[/red] {escape(str(error))}")
        raise typer.Exit(code=2) from error
    if not profiles:
        console.print(
            "[red]No inference connection is configured.[/red] "
            "Set ANTARES_ENDPOINT or create ~/.antares/profiles.toml."
        )
        raise typer.Exit(code=2)
    if len(profiles) == 1:
        selected_profile = profiles[0]
        console.print(f"\n  [dim]Using profile:[/dim] {escape(selected_profile.display)}")
        return selected_profile
    profile_index = _select_from_list("Profile", [p.display for p in profiles])
    return profiles[profile_index]


def _select_output(mode: str) -> tuple[Path | None, bool]:
    output_index = _select_from_list("Output", _output_options(mode))
    if output_index == 1:
        default_output = str(Path.cwd() / "antares-reports")
        raw_output = prompt(
            f"  Report directory [{default_output}]: ",
            completer=PathCompleter(expanduser=True),
        ).strip()
        return Path(raw_output or default_output).expanduser(), True
    return None, output_index != 2


def _output_options(mode: str) -> list[str]:
    return [
        "Default report directory — save JSON, Markdown, and SARIF",
        "Custom report directory  — save JSON, Markdown, and SARIF",
        "Do not save reports      — terminal/TUI output only",
    ]


def _confirm_wizard_result(result: WizardResult, profile_display: str) -> bool:
    confirmed = _confirm_launch(_summary_lines(result, profile_display))
    if not confirmed:
        console.print("  [dim]Cancelled.[/dim]")
    return confirmed


def _summary_lines(result: WizardResult, profile_display: str) -> list[tuple[str, str]]:
    summary_lines = [
        ("Target", str(result.target)),
        ("Mode", result.mode),
    ]
    if result.focus:
        summary_lines.append(("Focus", result.focus))
    summary_lines.append(("CWE IDs", result.cwe or "auto (repo-profiled)"))
    if result.mode == "sweep":
        summary_lines.append(("Workers", str(result.workers)))
        if not result.cwe:
            summary_lines.append(("Automatic CWE limit", str(result.max_cwes)))
    summary_lines.append(("Repository tool-call budget", str(result.terminal_call_budget)))
    summary_lines.append(("Profile", profile_display))
    if not result.reports_enabled:
        report_output = "disabled"
    elif result.output_path is not None:
        report_output = f"{result.output_path} (JSON, Markdown, SARIF)"
    else:
        report_output = "private Antares data directory (JSON, Markdown, SARIF)"
    summary_lines.append(("Reports", report_output))
    return summary_lines


def execute_wizard_result(result: WizardResult) -> None:
    """Execute the CWE query or sweep selected in the wizard."""
    _run_wizard_command(result)


def _wizard_argv(result: WizardResult) -> list[str]:
    """Build a synthetic argv representing the equivalent CLI invocation."""
    if result.mode == "query":
        argv = ["antares", "query", str(result.target)]
        if result.cwe:
            argv += ["--cwe", result.cwe]
        if result.focus:
            argv += ["--query", result.focus]
    else:
        argv = ["antares", "sweep", str(result.target)]
        if result.cwe:
            argv += ["--cwe", result.cwe]
        if result.focus:
            argv += ["--query", result.focus]
        argv += ["--workers", str(result.workers)]
        if not result.cwe:
            argv += ["--max-cwes", str(result.max_cwes)]
    argv += ["--tool-budget", str(result.terminal_call_budget)]
    argv += ["--profile", result.profile_name]
    if result.output_path:
        argv += ["--output", str(result.output_path)]
    if not result.reports_enabled:
        argv.append("--no-report")
    if result.output_format:
        argv += ["--format", result.output_format]
    return argv


def _run_wizard_command(result: WizardResult) -> None:
    invocation = capture_invocation(argv=_wizard_argv(result))
    if result.mode == "query":
        from antares_cli.commands.query import QueryCommandOptions, _run_query_command

        query_options = QueryCommandOptions(
            path=result.target,
            cwe=result.cwe or "",
            query=result.focus or None,
            output=result.output_path,
            output_format=result.output_format,
            profile=result.profile_name,
            model=None,
            backend=None,
            endpoint=None,
            fail_on_findings=False,
            export_path=None,
            terminal_call_budget=result.terminal_call_budget,
            allow_sensitive_files=(),
            reports_enabled=result.reports_enabled,
        )
        _run_query_command(query_options, invocation)
    else:
        from antares_cli.commands.sweep import SweepCommandOptions, _run_sweep_command

        sweep_options = SweepCommandOptions(
            path=result.target,
            query=result.focus or None,
            workers=result.workers,
            output=result.output_path,
            output_format=result.output_format,
            profile=result.profile_name,
            backend=None,
            endpoint=None,
            model=None,
            cwe=result.cwe,
            scope="auto",
            cwe_level="all",
            no_tui=False,
            fail_on_findings=False,
            export_path=None,
            terminal_call_budget=result.terminal_call_budget,
            allow_sensitive_files=(),
            max_cwes=result.max_cwes,
            reports_enabled=result.reports_enabled,
        )
        _run_sweep_command(sweep_options, invocation)
