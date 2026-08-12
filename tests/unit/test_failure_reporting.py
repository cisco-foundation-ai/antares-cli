# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import typer
from rich.console import Console

from antares_cli.agent.loop import AntaresAgentLoop
from antares_cli.agent.model_turn_stream import _http_error_message
from antares_cli.agent.subagent import SweepOrchestrator, WorkerTask
from antares_cli.agent.tool_router import ToolRouter
from antares_cli.agent.trace import investigation_trace_from_error
from antares_cli.commands._workflow import finalize_and_record_workflow_result
from antares_cli.core.service import (
    QueryRequest,
    SecurityWorkflowService,
    SweepRequest,
    WorkflowResult,
)
from antares_cli.inference.backend import InferenceBackend, InferenceError, InferenceStreamError
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.output.finding import ReportSummary
from antares_cli.output.report import write_report
from antares_cli.run_history import capture_invocation, record_failed_run


def test_http_authentication_errors_are_provider_neutral() -> None:
    request = httpx.Request("POST", "https://private-provider.example.test/v1/completions")

    unauthorized = httpx.HTTPStatusError(
        "provider-specific response",
        request=request,
        response=httpx.Response(401, request=request),
    )
    forbidden = httpx.HTTPStatusError(
        "provider-specific response",
        request=request,
        response=httpx.Response(403, request=request),
    )

    assert _http_error_message(unauthorized) == (
        "Inference endpoint authentication failed (HTTP 401). Check the configured credentials."
    )
    assert _http_error_message(forbidden) == (
        "Inference endpoint denied access (HTTP 403). Check the configured permissions."
    )


def test_other_http_errors_do_not_expose_endpoint_or_response_body() -> None:
    request = httpx.Request("POST", "https://private-provider.example.test/v1/completions")
    error = httpx.HTTPStatusError(
        "sensitive provider response",
        request=request,
        response=httpx.Response(422, request=request),
    )

    message = _http_error_message(error)

    assert message == "Inference endpoint request failed (HTTP 422)."
    assert "private-provider" not in message
    assert "sensitive" not in message


class _SoftFailureBackend(InferenceBackend):
    def __init__(self) -> None:
        super().__init__(model_id="test-model")

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        raise InferenceStreamError("malformed streamed response")


class _HardFailureBackend(InferenceBackend):
    def __init__(self) -> None:
        super().__init__(model_id="test-model")

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        raise InferenceError("Inference endpoint authentication failed (HTTP 401).")


class _IncompleteSubmissionBackend(InferenceBackend):
    def __init__(self) -> None:
        super().__init__(model_id="test-model")

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        yield (
            '<tool_call>{"name":"submit_vulnerable_files",'
            '"arguments":{"ranked_files":[]}}</tool_call>'
        )


class _RetryThenBlockedToolBackend(InferenceBackend):
    def __init__(self) -> None:
        super().__init__(model_id="test-model")
        self._responses = iter(
            [
                '<tool_call>{"name":"terminal","arguments":{"command":"pwd"}</tool_call>',
                '<tool_call>{"name":"terminal","arguments":{"command":"rm app.py"}}</tool_call>',
                '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
            ]
        )

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        yield next(self._responses)


class _ToolThenHardFailureBackend(InferenceBackend):
    def __init__(self) -> None:
        super().__init__(model_id="test-model")
        self._call_count = 0

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        self._call_count += 1
        if self._call_count == 1:
            yield '<tool_call>{"name":"terminal","arguments":{"command":"pwd"}}</tool_call>'
            return
        raise InferenceError("Inference endpoint authentication failed (HTTP 401).")


def test_query_result_preserves_generation_error_warning(tmp_path: Path) -> None:
    source_summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=1.0,
        cwe_ids_triggered=[],
        generation_errors=1,
    )
    agent_result = SimpleNamespace(findings=[], summary=source_summary)
    agent_loop = SimpleNamespace(run_audit=lambda *args, **kwargs: agent_result)
    settings = SimpleNamespace(
        model="test-model",
        backend="remote",
        ignore_paths=[],
        model_dump=lambda: {"model": "test-model", "backend": "remote"},
    )
    backend = SimpleNamespace(
        metadata=lambda: {
            "class": "TestBackend",
            "backend_name": "remote",
            "model_id": "test-model",
            "context_window": 32_768,
        }
    )
    runtime = SimpleNamespace(
        settings=settings,
        inference_backend=backend,
        cwe_database=CweDatabase.load_default(),
        model_label="test-model",
        selected_profile=None,
        model_spec=None,
        model_adapter=None,
        create_agent_loop=lambda target, **_kwargs: agent_loop,
    )
    runtime_factory = SimpleNamespace(build=lambda options: runtime)

    result = SecurityWorkflowService(runtime_factory=runtime_factory).run_query(
        QueryRequest(target=tmp_path, cwe_ids=["CWE-89"])
    )

    assert result.summary.generation_errors == 1
    assert result.to_dict()["warnings"] == [
        "Model backend error interrupted the scan (1 error(s)); results may be incomplete"
    ]


def test_query_passes_exact_sensitive_file_opt_in_to_agent_snapshot(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("API_KEY=example\n", encoding="utf-8")
    observed_allowed_paths: list[tuple[str, ...]] = []
    source_summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=0.1,
        cwe_ids_triggered=[],
    )
    agent_result = SimpleNamespace(findings=[], summary=source_summary)
    agent_loop = SimpleNamespace(run_audit=lambda *args, **kwargs: agent_result)
    settings = SimpleNamespace(
        model="test-model",
        backend="remote",
        ignore_paths=[],
        model_dump=lambda: {"model": "test-model", "backend": "remote"},
    )
    backend = SimpleNamespace(metadata=lambda: {"class": "TestBackend"})

    def create_agent_loop(_target: Path, *, snapshot) -> object:
        observed_allowed_paths.append(snapshot.allowed_sensitive_files)
        return agent_loop

    runtime = SimpleNamespace(
        settings=settings,
        inference_backend=backend,
        cwe_database=CweDatabase.load_default(),
        model_label="test-model",
        selected_profile=None,
        model_spec=None,
        model_adapter=None,
        create_agent_loop=create_agent_loop,
    )
    service = SecurityWorkflowService(
        runtime_factory=SimpleNamespace(build=lambda _options: runtime)
    )

    result = service.run_query(
        QueryRequest(
            target=tmp_path,
            cwe_ids=["CWE-89"],
            allow_sensitive_files=[".env.example"],
        )
    )

    assert observed_allowed_paths == [(".env.example",)]
    assert result.metadata["allowed_sensitive_files"] == [".env.example"]


def test_sweep_marks_soft_generation_error_worker_failed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    orchestrator = SweepOrchestrator(
        worker_count=1,
        inference_backend=_SoftFailureBackend(),
        tool_router_factory=ToolRouter,
        cwe_database=CweDatabase.load_default(),
    )

    result = orchestrator.run_orchestrated_sweep(
        tmp_path,
        [
            WorkerTask(
                description="Check for CWE-89",
                focus_cwe_ids=["CWE-89"],
            )
        ],
    )

    assert result.completed_task_count == 0
    assert result.failed_task_count == 1
    assert result.worker_results[0].generation_errors == 1
    assert result.worker_results[0].error_message == (
        "Model generation error interrupted this worker; results may be incomplete"
    )


def test_sweep_preserves_a_typed_inference_failure_as_a_failed_worker(
    tmp_path: Path,
) -> None:
    orchestrator = SweepOrchestrator(
        worker_count=1,
        inference_backend=_HardFailureBackend(),
        tool_router_factory=ToolRouter,
        cwe_database=CweDatabase.load_default(),
    )

    result = orchestrator.run_orchestrated_sweep(
        tmp_path,
        [WorkerTask(description="Check for CWE-89", focus_cwe_ids=["CWE-89"])],
    )

    assert result.completed_task_count == 0
    assert result.failed_task_count == 1
    assert result.worker_results[0].generation_errors == 1
    assert "authentication failed" in (result.worker_results[0].error_message or "")


def test_hard_failure_finalizes_and_links_its_investigation_trace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_ToolThenHardFailureBackend(),
    )

    with pytest.raises(InferenceError) as raised:
        agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    trace_path = investigation_trace_from_error(raised.value)
    assert trace_path is not None
    events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert [event["phase"] for event in events][-2:] == ["error", "done"]
    assert any(event["phase"] == "tool_result" for event in events)

    invocation = capture_invocation(argv=["antares", "query", "."], cwd=tmp_path)
    record = record_failed_run(
        invocation=invocation,
        mode="query",
        target=tmp_path,
        error=raised.value,
    )

    assert record["investigation_traces"] == [str(trace_path)]
    recorded_events = [
        json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    assert recorded_events[-1]["phase"] == "run_provenance"


def test_sweep_failed_worker_preserves_hard_failure_trace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    orchestrator = SweepOrchestrator(
        worker_count=1,
        inference_backend=_ToolThenHardFailureBackend(),
        tool_router_factory=ToolRouter,
        cwe_database=CweDatabase.load_default(),
    )

    result = orchestrator.run_orchestrated_sweep(
        tmp_path,
        [WorkerTask(description="Check for CWE-89", focus_cwe_ids=["CWE-89"])],
    )

    assert result.failed_task_count == 1
    investigation_trace = result.worker_results[0].investigation_trace
    assert investigation_trace is not None
    trace_path = Path(investigation_trace)
    assert trace_path.exists()
    phases = [
        json.loads(line)["phase"] for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    assert phases[-2:] == ["error", "done"]


def test_sweep_marks_missing_valid_submission_as_a_failed_worker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    orchestrator = SweepOrchestrator(
        worker_count=1,
        inference_backend=_IncompleteSubmissionBackend(),
        tool_router_factory=ToolRouter,
        cwe_database=CweDatabase.load_default(),
    )

    result = orchestrator.run_orchestrated_sweep(
        tmp_path,
        [WorkerTask(description="Check for CWE-89", focus_cwe_ids=["CWE-89"])],
    )

    assert result.completed_task_count == 0
    assert result.failed_task_count == 1
    assert result.worker_results[0].generation_errors == 0
    assert result.worker_results[0].error_message == (
        "Model submitted no valid repository file paths."
    )


def test_sweep_result_aggregates_generation_error_warning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    settings = SimpleNamespace(
        model="test-model",
        backend="remote",
        ignore_paths=[],
        model_dump=lambda: {"model": "test-model", "backend": "remote"},
    )
    backend = _SoftFailureBackend()
    runtime = SimpleNamespace(
        settings=settings,
        inference_backend=backend,
        cwe_database=CweDatabase.load_default(),
        model_label="test-model",
        selected_profile=None,
        model_spec=None,
        model_adapter=None,
    )
    runtime_factory = SimpleNamespace(build=lambda options: runtime)

    result = SecurityWorkflowService(runtime_factory=runtime_factory).run_cwe_sweep(
        SweepRequest(target=tmp_path, cwe_ids=["CWE-89"], workers=1)
    )

    assert result.summary.generation_errors == 1
    assert result.summary.failed_workers == 1
    assert result.per_cwe_results[0]["investigation_trace"] is not None
    assert result.to_dict()["warnings"] == [
        "Model backend error interrupted the scan (1 error(s)); results may be incomplete",
        "1/1 CWE workers failed; some vulnerability classes were not scanned",
    ]


def test_sweep_aggregates_worker_tool_failures_and_parse_retries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    settings = SimpleNamespace(
        model="test-model",
        backend="remote",
        ignore_paths=[],
        model_dump=lambda: {"model": "test-model", "backend": "remote"},
    )
    runtime = SimpleNamespace(
        settings=settings,
        inference_backend=_RetryThenBlockedToolBackend(),
        cwe_database=CweDatabase.load_default(),
        model_label="test-model",
        selected_profile=None,
        model_spec=None,
        model_adapter=None,
    )
    runtime_factory = SimpleNamespace(build=lambda options: runtime)

    result = SecurityWorkflowService(runtime_factory=runtime_factory).run_cwe_sweep(
        SweepRequest(target=tmp_path, cwe_ids=["CWE-89"], workers=1)
    )

    assert result.summary.failed_tool_calls == 1
    assert result.summary.retried_turns == 1
    assert result.summary.failed_workers == 0
    assert result.per_cwe_results[0]["failed_tool_calls"] == 1
    assert result.per_cwe_results[0]["retried_turns"] == 1


def test_write_report_preserves_warnings_in_every_format(tmp_path: Path) -> None:
    summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=1.0,
        cwe_ids_triggered=[],
        generation_errors=1,
        failed_workers=1,
        total_workers=2,
    )
    expected_warnings = [
        "Model backend error interrupted the scan (1 error(s)); results may be incomplete",
        "1/2 CWE workers failed; some vulnerability classes were not scanned",
    ]

    json_path = write_report(tmp_path / "report.json", [], summary, output_format="json")
    markdown_path = write_report(tmp_path / "report.md", [], summary, output_format="markdown")
    sarif_path = write_report(tmp_path / "report.sarif", [], summary, output_format="sarif")

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    sarif_payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    markdown_text = markdown_path.read_text(encoding="utf-8")

    assert json_payload["summary"]["generation_errors"] == 1
    assert json_payload["summary"]["failed_workers"] == 1
    assert json_payload["summary"]["total_workers"] == 2
    assert json_payload["warnings"] == expected_warnings
    assert all(warning in markdown_text for warning in expected_warnings)
    assert sarif_payload["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_incomplete_submission_is_a_warning_and_unsuccessful_sarif_run(
    tmp_path: Path,
) -> None:
    reason = "Model ended without an explicit final submission."
    summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=1.0,
        cwe_ids_triggered=[],
        incomplete_reason=reason,
    )

    json_path = write_report(tmp_path / "report.json", [], summary, output_format="json")
    sarif_path = write_report(tmp_path / "report.sarif", [], summary, output_format="sarif")

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    sarif_payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert json_payload["warnings"] == [reason]
    assert json_payload["summary"]["incomplete_reason"] == reason
    assert sarif_payload["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_partial_scan_is_recorded_and_exits_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    report_directory = tmp_path / "partial-reports"
    result = WorkflowResult(
        findings=[],
        summary=ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=1.0,
            cwe_ids_triggered=[],
            generation_errors=1,
        ),
        metadata={"mode": "query", "model": "test-model", "backend": "remote"},
    )
    invocation = capture_invocation(argv=["antares", "query", "."], cwd=tmp_path)

    with pytest.raises(typer.Exit) as raised:
        finalize_and_record_workflow_result(
            result,
            invocation=invocation,
            target=tmp_path,
            report_directory=report_directory,
            report_formats=("json", "markdown", "sarif"),
            stdout_format=None,
            console=Console(file=None),
        )

    assert raised.value.exit_code == 2
    assert {path.name for path in report_directory.iterdir()} == {
        "report.json",
        "report.md",
        "report.sarif",
    }
    run_manifest = tmp_path / "antares-data" / "runs" / f"{invocation.execution_id}.json"
    assert run_manifest.exists()
    assert json.loads(run_manifest.read_text(encoding="utf-8"))["status"] == "incomplete"


def test_incomplete_scan_is_recorded_and_exits_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    report_directory = tmp_path / "incomplete-reports"
    result = WorkflowResult(
        findings=[],
        summary=ReportSummary(
            total_findings=0,
            tool_call_count=0,
            duration_seconds=1.0,
            cwe_ids_triggered=[],
            incomplete_reason="Model ended without an explicit final submission.",
        ),
        metadata={"mode": "query", "model": "test-model", "backend": "remote"},
    )
    invocation = capture_invocation(argv=["antares", "query", "."], cwd=tmp_path)

    with pytest.raises(typer.Exit) as raised:
        finalize_and_record_workflow_result(
            result,
            invocation=invocation,
            target=tmp_path,
            report_directory=report_directory,
            report_formats=("json", "markdown", "sarif"),
            stdout_format=None,
            console=Console(file=None),
        )

    assert raised.value.exit_code == 2
    assert (report_directory / "report.json").exists()
    run_manifest = tmp_path / "antares-data" / "runs" / f"{invocation.execution_id}.json"
    assert json.loads(run_manifest.read_text(encoding="utf-8"))["status"] == "incomplete"
