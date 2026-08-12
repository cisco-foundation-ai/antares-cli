# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Main Typer application for Antares CLI."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Protocol, cast

import typer
import typer.completion as typer_completion
from rich.console import Console

from antares_cli import __version__
from antares_cli.commands._interaction import can_interact
from antares_cli.commands.models import models_app
from antares_cli.commands.plan import plan_command
from antares_cli.commands.query import query_command
from antares_cli.commands.runs import runs_app
from antares_cli.commands.sweep import sweep_command
from antares_cli.commands.tool import tool_app


class _CompletionApi(Protocol):
    completion_init: Callable[[], None]
    get_completion_script: Callable[..., str]


# Typer exposes these functions at runtime but omits them from its type exports.
_completion_api = cast(_CompletionApi, typer_completion)
_completion_api.completion_init()


class CompletionShell(StrEnum):
    bash = "bash"
    zsh = "zsh"
    fish = "fish"
    powershell = "powershell"
    pwsh = "pwsh"


app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Antares — model-assisted file-level vulnerability localization for source repositories.",
    invoke_without_command=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"antares-cli {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    _version: bool = typer.Option(
        False,
        "--version",
        help="Show the Antares CLI version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    if ctx.invoked_subcommand is None:
        if can_interact():
            from antares_cli.commands.wizard import execute_wizard_result, run_wizard

            result = run_wizard()
            if result is not None:
                execute_wizard_result(result)
            raise typer.Exit()
        console.print(ctx.get_help())


app.command("query")(query_command)
app.command("sweep")(sweep_command)
app.command("plan")(plan_command)
app.add_typer(models_app, name="models")
app.add_typer(runs_app, name="runs")
app.add_typer(tool_app, name="tool")


@app.command("completion")
def completion_command(
    shell: CompletionShell = typer.Argument(
        ..., help="Shell whose completion script should be generated."
    ),
) -> None:
    """Generate a shell completion script from the live command tree."""
    completion_parameters = {
        "prog_name": "antares",
        "complete_var": "_ANTARES_COMPLETE",
        "shell": shell.value,
    }
    typer.echo(_completion_api.get_completion_script(**completion_parameters))
