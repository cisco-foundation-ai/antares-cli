# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared execution-policy contracts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

import antares_cli.commands.query as query_module
import antares_cli.commands.sweep as sweep_module
import antares_cli.commands.wizard as wizard_module
from antares_cli.agent.execution_policy import (
    DEFAULT_TERMINAL_CALL_BUDGET,
    MAX_TERMINAL_CALL_BUDGET,
    resolve_terminal_call_budget,
)
from antares_cli.agent.loop import AntaresAgentLoop
from antares_cli.agent.model_adapter import ANTARES_ADAPTER
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.config import AntaresSettings
from antares_cli.core.runtime import RuntimeContext, RuntimeOptions
from antares_cli.core.service import (
    QueryRequest,
    SecurityWorkflowService,
    SweepRequest,
)
from antares_cli.inference.backend import InferenceBackend
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.main import app

runner = CliRunner()


class _RecordingBackend(InferenceBackend):
    def __init__(self, responses: list[str] | None = None) -> None:
        super().__init__(model_id="test-model")
        self.message_batches: list[list[dict[str, str]]] = []
        self._responses = iter(
            responses
            or ['<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>']
        )

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        self.message_batches.append([dict(message) for message in messages])
        yield next(self._responses)


class _StaticRuntimeFactory:
    def __init__(self, backend: InferenceBackend) -> None:
        self.backend = backend
        self.cwe_database = CweDatabase.load_default()

    def build(self, _options: RuntimeOptions) -> RuntimeContext:
        return RuntimeContext(
            settings=AntaresSettings(model="test-model", backend="remote"),
            inference_backend=self.backend,
            cwe_database=self.cwe_database,
            model_label="test-model",
            selected_profile=None,
            model_spec=None,
            model_adapter=ANTARES_ADAPTER,
        )

    def load_cwe_database(self) -> CweDatabase:
        return self.cwe_database


def test_terminal_call_budget_defaults_to_fifteen() -> None:
    assert DEFAULT_TERMINAL_CALL_BUDGET == 15
    assert resolve_terminal_call_budget(None) == 15


@pytest.mark.parametrize("value", [0, 51])
def test_terminal_call_budget_rejects_values_outside_one_to_fifty(value: int) -> None:
    assert MAX_TERMINAL_CALL_BUDGET == 50
    with pytest.raises(ValueError, match="between 1 and 50"):
        resolve_terminal_call_budget(value)


def test_antares_prompt_uses_the_resolved_budget_without_a_minimum_call_quota() -> None:
    prompt = ANTARES_ADAPTER.build_system_prompt(terminal_call_budget=23)

    assert "You have up to 23 repository tool calls" in prompt
    assert "7-10 terminal calls" not in prompt


def test_direct_agent_run_uses_the_same_budget_in_state_and_prompt(tmp_path: Path) -> None:
    backend = _RecordingBackend()
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"], terminal_call_budget=31)

    system_prompt = backend.message_batches[0][0]["content"]
    assert "You have up to 31 repository tool calls" in system_prompt


def test_query_and_sweep_requests_share_the_fifteen_call_default(tmp_path: Path) -> None:
    assert QueryRequest(target=tmp_path).terminal_call_budget == 15
    assert SweepRequest(target=tmp_path).terminal_call_budget == 15


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_interactive_commands_reject_tool_budgets_above_fifty(
    command: str,
    tmp_path: Path,
) -> None:
    arguments = [command, str(tmp_path), "--tool-budget", "51"]
    if command == "query":
        arguments.extend(["--cwe", "CWE-89"])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "50" in result.output


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_interactive_command_help_exposes_the_shared_default(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code == 0
    assert "default: 15" in result.output


@pytest.mark.parametrize("mode", ["query", "sweep"])
def test_wizard_propagates_a_tool_budget_override(
    mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[query_module.QueryCommandOptions | sweep_module.SweepCommandOptions] = []
    result = wizard_module.WizardResult(
        target=tmp_path,
        mode=mode,
        focus="",
        profile_name="test-profile",
        output_path=None,
        output_format=None,
        workers=1,
        terminal_call_budget=42,
        cwe="CWE-89" if mode == "query" else None,
    )

    monkeypatch.setattr(wizard_module, "capture_invocation", lambda argv: argv)

    def capture_options(
        options: query_module.QueryCommandOptions | sweep_module.SweepCommandOptions,
        _invocation: object,
    ) -> None:
        captured.append(options)

    command_module = query_module if mode == "query" else sweep_module
    command_name = "_run_query_command" if mode == "query" else "_run_sweep_command"
    monkeypatch.setattr(command_module, command_name, capture_options)

    wizard_module._run_wizard_command(result)

    assert len(captured) == 1
    assert captured[0].terminal_call_budget == 42
    assert wizard_module._wizard_argv(result)[-4:] == [
        "--tool-budget",
        "42",
        "--profile",
        "test-profile",
    ]
    assert ("Repository tool-call budget", "42") in wizard_module._summary_lines(
        result, "Test profile"
    )


def test_wizard_propagates_sweep_instructions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = wizard_module.WizardResult(
        target=tmp_path,
        mode="sweep",
        focus="Prioritize authentication boundaries",
        profile_name="test-profile",
        output_path=None,
        output_format=None,
        workers=2,
        cwe="CWE-287,CWE-862",
    )
    captured: list[sweep_module.SweepCommandOptions] = []
    monkeypatch.setattr(wizard_module, "capture_invocation", lambda argv: argv)
    monkeypatch.setattr(
        sweep_module,
        "_run_sweep_command",
        lambda options, _invocation: captured.append(options),
    )

    wizard_module._run_wizard_command(result)

    assert captured[0].query == "Prioritize authentication boundaries"
    argv = wizard_module._wizard_argv(result)
    query_index = argv.index("--query")
    assert argv[query_index : query_index + 2] == [
        "--query",
        "Prioritize authentication boundaries",
    ]


def test_wizard_tool_budget_prompt_retries_until_the_override_is_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(["not-a-number", "51", "42"])
    monkeypatch.setattr(wizard_module, "prompt", lambda *_args, **_kwargs: next(answers))

    assert wizard_module._prompt_tool_budget() == 42


def test_wizard_tool_budget_prompt_uses_the_shared_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wizard_module, "prompt", lambda *_args, **_kwargs: "")

    assert wizard_module._prompt_tool_budget() == DEFAULT_TERMINAL_CALL_BUDGET


def test_wizard_expands_the_user_home_in_report_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wizard_module, "_select_from_list", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        wizard_module,
        "prompt",
        lambda *_args, **_kwargs: "~/reports/scan",
    )

    output_path, reports_enabled = wizard_module._select_output("query")

    assert output_path == tmp_path / "reports" / "scan"
    assert reports_enabled is True


def test_wizard_can_disable_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wizard_module, "_select_from_list", lambda *_args, **_kwargs: 2)

    output_path, reports_enabled = wizard_module._select_output("sweep")

    assert output_path is None
    assert reports_enabled is False


@pytest.mark.parametrize("command", ["query", "sweep"])
def test_json_tool_commands_validate_the_same_budget_range(
    command: str,
    tmp_path: Path,
) -> None:
    payload: dict[str, object] = {
        "target": str(tmp_path),
        "cwe_ids": ["CWE-89"],
        "tool_budget": 51,
    }

    result = runner.invoke(
        app,
        ["tool", command, "--stdin"],
        input=json.dumps(payload),
    )

    assert result.exit_code == 2
    assert "between 1 and 50" in result.output


@pytest.mark.parametrize("value", [True, 3.5, "not-a-number"])
def test_json_tool_budget_requires_an_integer(value: object, tmp_path: Path) -> None:
    payload = {
        "target": str(tmp_path),
        "cwe_ids": ["CWE-89"],
        "tool_budget": value,
    }

    result = runner.invoke(
        app,
        ["tool", "query", "--stdin"],
        input=json.dumps(payload),
        env={"ANTARES_ENDPOINT": "", "ANTARES_API_KEY": ""},
    )

    assert result.exit_code == 2
    assert "tool_budget must be an integer" in result.output


def test_terminal_execution_is_blocked_after_the_resolved_budget(tmp_path: Path) -> None:
    source_path = tmp_path / "sample.txt"
    source_path.write_text("first\nsecond\nthird\n", encoding="utf-8")
    responses = [
        '<tool_call>{"name":"terminal","arguments":{"command":"head -n 1 sample.txt"}}</tool_call>',
        '<tool_call>{"name":"terminal","arguments":{"command":"sed -n 2p sample.txt"}}</tool_call>',
        '<tool_call>{"name":"terminal","arguments":{"command":"tail -n 1 sample.txt"}}</tool_call>',
        '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
    ]
    backend = _RecordingBackend(responses)
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"], terminal_call_budget=2)

    blocked_response = backend.message_batches[3][-1]["content"]
    assert "Terminal call budget exhausted (2/2)" in blocked_response
    assert "third" not in blocked_response
    assert result.summary.failed_tool_calls == 1
    assert result.summary.tool_call_count == 4


def test_zero_argument_submission_ends_run_after_budget_exhaustion(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("content\n", encoding="utf-8")
    backend = _RecordingBackend(
        [
            '<tool_call>{"name":"terminal","arguments":{"command":"cat sample.txt"}}</tool_call>',
            '<tool_call>{"name":"submit_no_vulnerability_found"}</tool_call>',
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(
        tmp_path,
        focus_cwe_ids=["CWE-89"],
        terminal_call_budget=1,
    )

    assert len(backend.message_batches) == 2
    assert result.summary.incomplete_reason is None
    assert result.summary.failed_tool_calls == 0
    assert result.summary.tool_call_count == 2


def test_budget_exhaustion_enters_bounded_submission_mode(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("content\n", encoding="utf-8")
    malformed_submission = '<tool_call>{"name":"terminal"}</tool_call>'
    backend = _RecordingBackend(
        [
            '<tool_call>{"name":"terminal","arguments":{"command":"cat sample.txt"}}</tool_call>',
            *([malformed_submission] * 3),
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(
        tmp_path,
        focus_cwe_ids=["CWE-89"],
        terminal_call_budget=1,
    )

    retry_messages = [
        message["content"]
        for message_batch in backend.message_batches
        for message in message_batch
        if message["role"] == "tool_response"
    ]
    assert len(backend.message_batches) == 4
    assert all("Continue investigating" not in message for message in retry_messages)
    assert all("You must use tools" not in message for message in retry_messages)
    assert any("submit_no_vulnerability_found" in message for message in retry_messages)
    assert result.summary.incomplete_reason == "Model ended without an explicit final submission."
    assert result.summary.retried_turns == 0
    assert result.summary.tool_call_count == 1


@pytest.mark.parametrize(
    "tool_call",
    [
        '<tool_call>{"name":"terminal","arguments":{"command":"rm sample.txt"}}</tool_call>',
        '<tool_call>{"name":"unsupported_tool","arguments":{}}</tool_call>',
        '<tool_call>{"name":"read_file","arguments":{"path":"missing.py"}}</tool_call>',
    ],
)
def test_rejected_or_failed_tool_invocations_are_counted(
    tmp_path: Path,
    tool_call: str,
) -> None:
    (tmp_path / "sample.txt").write_text("content\n", encoding="utf-8")
    backend = _RecordingBackend(
        [
            tool_call,
            '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert result.summary.failed_tool_calls == 1
    assert result.summary.tool_call_count == 2


def test_duplicate_tool_invocations_are_counted_as_failed_attempts(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("content\n", encoding="utf-8")
    repeated_call = '<tool_call>{"name":"read_file","arguments":{"path":"sample.txt"}}</tool_call>'
    backend = _RecordingBackend(
        [
            repeated_call,
            repeated_call,
            '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    events = [
        json.loads(line)
        for line in result.investigation_trace.read_text(encoding="utf-8").splitlines()
    ]
    tool_call_events = [event for event in events if event["phase"] == "tool_call"]
    duplicate_blocked_events = [
        event
        for event in events
        if event["phase"] == "tool_blocked"
        and event["payload"]["reason"] == "Skipped duplicate tool call: read_file"
    ]
    duplicate_result_events = [
        event
        for event in events
        if event["phase"] == "tool_result" and event["evidence_id"] == "duplicate_tool_call"
    ]
    assert result.summary.failed_tool_calls == 1
    assert result.summary.tool_call_count == 3
    assert len(tool_call_events) == result.summary.tool_call_count
    assert len(duplicate_blocked_events) == 1
    assert len(duplicate_result_events) == 1


def test_query_and_sweep_report_the_same_resolved_budget(tmp_path: Path) -> None:
    query_backend = _RecordingBackend()
    sweep_backend = _RecordingBackend()
    query_result = SecurityWorkflowService(
        runtime_factory=_StaticRuntimeFactory(query_backend)
    ).run_query(QueryRequest(target=tmp_path, cwe_ids=["CWE-89"], terminal_call_budget=27))
    sweep_result = SecurityWorkflowService(
        runtime_factory=_StaticRuntimeFactory(sweep_backend)
    ).run_cwe_sweep(
        SweepRequest(
            target=tmp_path,
            cwe_ids=["CWE-89"],
            workers=1,
            terminal_call_budget=27,
        )
    )

    assert query_result.metadata["terminal_call_budget"] == 27
    assert sweep_result.metadata["terminal_call_budget"] == 27
    assert query_backend.message_batches[0] == sweep_backend.message_batches[0]
    assert (
        "You have up to 27 repository tool calls" in query_backend.message_batches[0][0]["content"]
    )
