# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inference profile inspection commands."""

from __future__ import annotations

import typer
from rich.console import Console

from antares_cli.inference.profiles import ProfileConfigurationError, load_profiles
from antares_cli.output.renderer import render_key_value_panel

models_app = typer.Typer(help="Inspect configured inference profiles.")
console = Console()


@models_app.command("list")
def list_profiles_command() -> None:
    """Show all available inference profiles."""
    try:
        profiles = load_profiles()
    except ProfileConfigurationError as error:
        raise typer.BadParameter(str(error)) from error
    if not profiles:
        console.print(
            "No inference profiles are configured. Set ANTARES_ENDPOINT and ANTARES_MODEL, "
            "or create ~/.antares/profiles.toml."
        )
        return
    for profile in profiles:
        console.print(
            render_key_value_panel(
                "PROFILE",
                [
                    ("Name", profile.name),
                    ("Backend", profile.backend),
                    ("Model", profile.model_id),
                    ("Adapter", profile.adapter),
                    ("Endpoint", profile.endpoint_display),
                    ("Description", profile.description),
                    ("Use Cases", ", ".join(profile.recommended_use_cases)),
                ],
            )
        )
