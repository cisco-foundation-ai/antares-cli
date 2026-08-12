# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Terminal output must preserve complete keys and values at narrow widths."""

from __future__ import annotations

from rich.console import Console
from typer.testing import CliRunner

import antares_cli.commands.models as models_command
import antares_cli.commands.runs as runs_command
from antares_cli.inference.profiles import InferenceProfile
from antares_cli.main import app

runner = CliRunner()


def _compact_rendered_text(text: str) -> str:
    box_characters = "│╭╮╰╯─"
    return "".join(
        character
        for character in text
        if not character.isspace() and character not in box_characters
    )


def test_runs_list_preserves_full_values_at_narrow_width(monkeypatch) -> None:
    target = "/home/developer/projects/a-very-long-repository-name"
    command = "antares query /home/developer/projects/a-very-long-repository-name --cwe CWE-89"
    commit = "0123456789abcdef0123456789abcdef01234567"
    record = {
        "execution_id": "abcdefghijkl",
        "status": "completed",
        "mode": "query",
        "target": target,
        "invocation": {"started_at": "2026-07-07T19:00:00Z", "command": command},
        "target_git": {"commit": commit, "dirty": False},
        "investigation_traces": ["/tmp/run.investigation.jsonl"],
    }
    console = Console(record=True, width=72, force_terminal=False)
    monkeypatch.setattr(runs_command, "console", console)
    monkeypatch.setattr(runs_command, "load_run_records", lambda limit: [record])

    runs_command.list_runs_command(limit=20, last=None, json_output=False)

    rendered = console.export_text()
    compact = _compact_rendered_text(rendered)
    assert "…" not in rendered
    assert _compact_rendered_text(target) in compact
    assert _compact_rendered_text(command) in compact
    assert commit in compact


def test_models_list_preserves_full_values_at_narrow_width(monkeypatch) -> None:
    endpoint = "https://inference.example.test/a/very/long/openai-compatible-endpoint"
    description = "A complete description that must wrap without losing any words"
    profile = InferenceProfile(
        name="long-profile-name",
        display_name="Long profile",
        backend="remote",
        model_id="provider/model-with-a-long-name",
        adapter="antares",
        endpoint=endpoint,
        description=description,
        recommended_use_cases=["security review", "vulnerability localization"],
    )
    console = Console(record=True, width=72, force_terminal=False)
    monkeypatch.setattr(models_command, "console", console)
    monkeypatch.setattr(models_command, "load_profiles", lambda: [profile])

    models_command.list_profiles_command()

    rendered = console.export_text()
    compact = _compact_rendered_text(rendered)
    assert _compact_rendered_text("https://inference.example.test/…") in compact
    assert "openai-compatible-endpoint" not in rendered
    assert _compact_rendered_text(description) in compact
    assert _compact_rendered_text(profile.model_id) in compact


def test_models_list_reports_malformed_profile_toml_without_traceback(
    tmp_path, monkeypatch
) -> None:
    config_dir = tmp_path / ".antares"
    config_dir.mkdir()
    (config_dir / "profiles.toml").write_text("[profiles.invalid\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))

    result = runner.invoke(app, ["models", "list"])

    assert result.exit_code == 2
    assert "Invalid inference profile configuration" in result.output
    assert "Traceback" not in result.output
