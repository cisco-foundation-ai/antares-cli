# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Validation contracts for the non-interactive JSON command surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from antares_cli.core.service import SecurityWorkflowService, WorkflowResult
from antares_cli.main import app
from antares_cli.output.finding import ReportSummary

runner = CliRunner()


@pytest.mark.parametrize(
    ("command", "payload", "message"),
    [
        ("query", {"target": None, "cwe_ids": ["CWE-89"]}, "target must be"),
        ("query", {"target": "missing-repository", "cwe_ids": ["CWE-89"]}, "does not exist"),
        ("query", {"target": ".", "cwe_ids": [89]}, "entries must be strings"),
        (
            "query",
            {"target": ".", "cwe_ids": ["CWE-89"], "profile": {"name": "bad"}},
            "profile must be a string or null",
        ),
        ("sweep", {"target": ".", "workers": "many"}, "workers must be"),
        ("sweep", {"target": ".", "workers": 0}, "workers must be"),
        ("sweep", {"target": ".", "workers": 33}, "between 1 and 32"),
        ("sweep", {"target": ".", "scope": ["auto"]}, "scope must be a string"),
        ("query", {"target": ".", "cwe_ids": ["CWE-89"], "typo": 1}, "Unknown query"),
        (
            "query",
            {
                "target": ".",
                "cwe_ids": ["CWE-89"],
                "allow_sensitive_files": ".env",
            },
            "must be an array",
        ),
        ("sweep", {"target": ".", "selection": []}, "selection must be an object"),
        (
            "sweep",
            {"target": ".", "selection": {"scope": "auto", "typo": 1}},
            "Unknown selection",
        ),
        (
            "sweep",
            {"target": ".", "scope": "auto", "selection": {"scope": "owasp"}},
            "not both",
        ),
    ],
)
def test_invalid_json_fields_fail_cleanly(
    command: str,
    payload: dict[str, object],
    message: str,
) -> None:
    result = runner.invoke(
        app,
        ["tool", command, "--stdin"],
        input=json.dumps(payload),
    )

    assert result.exit_code == 2
    assert message in " ".join(result.output.split())
    assert "Traceback" not in result.output


def test_non_object_json_fails_cleanly() -> None:
    result = runner.invoke(app, ["tool", "query", "--stdin"], input="[]")

    assert result.exit_code == 2
    assert "stdin JSON must be an object" in " ".join(result.output.split())
    assert "Traceback" not in result.output


def test_oversized_stdin_json_fails_before_parsing() -> None:
    result = runner.invoke(
        app,
        ["tool", "query", "--stdin"],
        input='{"padding":"' + ("x" * 1_000_000) + '"}',
    )

    assert result.exit_code == 2
    assert "character limit" in result.output
    assert "Traceback" not in result.output


def test_deeply_nested_stdin_json_fails_cleanly() -> None:
    nested_json = '{"x":' + ("[" * 2_000) + "0" + ("]" * 2_000) + "}"

    result = runner.invoke(app, ["tool", "query", "--stdin"], input=nested_json)

    assert result.exit_code == 2
    assert "nesting exceeds 256 levels" in result.output
    assert "Traceback" not in result.output


def test_tool_query_emits_completed_json_when_private_history_is_unwritable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_payload = WorkflowResult(
        findings=[],
        summary=ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=0.1,
            cwe_ids_triggered=[],
        ),
        metadata={"mode": "query"},
    )
    monkeypatch.setattr(
        SecurityWorkflowService,
        "run_query",
        lambda *_args, **_kwargs: result_payload,
    )

    result = runner.invoke(
        app,
        ["tool", "query", "--stdin"],
        input=json.dumps({"target": str(tmp_path), "cwe_ids": ["CWE-89"]}),
        env={"ANTARES_DATA_DIR": "/dev/null"},
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["total_findings"] == 0
    assert "could not save private run history" in result.stderr
    assert "Traceback" not in result.output


def test_tool_query_accepts_exact_sensitive_file_array(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".env.example").write_text("API_KEY=example\n", encoding="utf-8")
    captured_requests: list[object] = []
    result_payload = WorkflowResult(
        findings=[],
        summary=ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=0.1,
            cwe_ids_triggered=[],
        ),
        metadata={"mode": "query"},
    )

    def run_query(_service, request):
        captured_requests.append(request)
        return result_payload

    monkeypatch.setattr(SecurityWorkflowService, "run_query", run_query)

    result = runner.invoke(
        app,
        ["tool", "query", "--stdin"],
        input=json.dumps(
            {
                "target": str(tmp_path),
                "cwe_ids": ["CWE-89"],
                "allow_sensitive_files": [".env.example"],
            }
        ),
        env={"ANTARES_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 0
    assert captured_requests[0].allow_sensitive_files == [".env.example"]


def test_tool_query_preserves_original_error_when_failure_history_is_unwritable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_query(*_args, **_kwargs):
        raise ValueError("original configuration failure")

    monkeypatch.setattr(SecurityWorkflowService, "run_query", fail_query)

    result = runner.invoke(
        app,
        ["tool", "query", "--stdin"],
        input=json.dumps({"target": str(tmp_path), "cwe_ids": ["CWE-89"]}),
        env={"ANTARES_DATA_DIR": "/dev/null"},
    )

    assert result.exit_code == 2
    assert "original configuration failure" in result.output
    assert "could not save private run history" in result.output
    assert "Traceback" not in result.output
