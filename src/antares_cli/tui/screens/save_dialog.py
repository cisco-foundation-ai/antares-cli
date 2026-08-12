# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Save report dialog — modal screen for choosing format and path."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from antares_cli.core.service import WorkflowResult
from antares_cli.output.report import infer_output_format, write_report, write_report_text


class SaveDialog(ModalScreen[str | None]):
    """Modal for saving findings as a report file."""

    DEFAULT_CSS = """
    SaveDialog {
        align: center middle;
    }

    #save-container {
        width: 60;
        height: auto;
        background: $surface;
        border: round #444444;
        padding: 1 2;
    }

    #save-title {
        text-style: bold;
        margin-bottom: 1;
    }

    #save-hint {
        color: $text-muted;
        margin-bottom: 1;
    }

    #save-input {
        margin-bottom: 1;
    }

    #save-status {
        color: $text-muted;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(
        self,
        result: WorkflowResult,
        default_path: Path | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._result = result
        self._default_path = default_path or Path(tempfile.gettempdir()) / "antares-report.json"

    def compose(self) -> ComposeResult:
        with Vertical(id="save-container"):
            yield Static("Save Report", id="save-title")
            yield Static(
                "Format inferred from extension: .json .md .sarif",
                id="save-hint",
            )
            yield Input(
                placeholder=str(self._default_path),
                value=str(self._default_path),
                id="save-input",
            )
            yield Static("", id="save-status", markup=False)

    def on_mount(self) -> None:
        self.query_one("#save-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        path_str = event.value.strip()
        if not path_str:
            self.dismiss(None)
            return

        output_path = Path(path_str).expanduser()
        status = self.query_one("#save-status", Static)

        try:
            if infer_output_format(output_path) == "json":
                written = write_report_text(output_path, self._result.to_json())
            else:
                written = write_report(
                    output_path,
                    self._result.findings,
                    self._result.summary,
                    per_cwe_results=self._result.per_cwe_results,
                )
            self.dismiss(str(written))
        except Exception as error:
            status.update(f"Error: {error}")

    def action_cancel(self) -> None:
        self.dismiss(None)
