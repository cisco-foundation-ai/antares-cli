# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from antares_cli.agent.contracts import (
    RANKED_FILES_ARGUMENT,
    SUBMIT_VULNERABLE_FILES_TOOL,
    is_submit_tool_call,
)
from antares_cli.agent.loop import AntaresAgentLoop
from antares_cli.agent.model_adapter import ANTARES_ADAPTER
from antares_cli.agent.streaming import ParsedToolCall
from antares_cli.agent.tool_router import MAX_TOOL_ERROR_CHARS, ToolRouter
from antares_cli.agent.transcript import (
    estimate_transcript_token_upper_bound,
    prompt_token_budget,
)
from antares_cli.inference.backend import (
    InferenceBackend,
    InferenceContextLengthError,
)
from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.tools.readonly_workspace import ReadOnlyRepositorySnapshot


class _SingleTurnBackend(InferenceBackend):
    def __init__(self, response: str) -> None:
        super().__init__(model_id="test-model")
        self._response = response

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        yield self._response


class _SequenceBackend(InferenceBackend):
    def __init__(self, responses: list[str]) -> None:
        super().__init__(model_id="test-model")
        self._responses = iter(responses)
        self.message_batches: list[list[dict[str, str]]] = []

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        self.message_batches.append([message.copy() for message in messages])
        yield next(self._responses)


class _ContextRejectingBackend(InferenceBackend):
    max_tokens = 4_096

    def __init__(self, *, reject_every_attempt: bool = False) -> None:
        super().__init__(model_id="test-model", context_window=16_384)
        self.reject_every_attempt = reject_every_attempt
        self.message_batches: list[list[dict[str, str]]] = []

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        self.message_batches.append([message.copy() for message in messages])
        if self.reject_every_attempt or len(self.message_batches) == 1:
            raise InferenceContextLengthError(
                "Inference request exceeded the model context capacity."
            )
        yield '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>'


def test_adapter_uses_shared_submit_contract() -> None:
    payload = {
        "name": SUBMIT_VULNERABLE_FILES_TOOL,
        "arguments": {RANKED_FILES_ARGUMENT: ["src/auth.py"]},
    }
    calls = ANTARES_ADAPTER.extract_submit_tool_calls(
        f"<tool_call>\n{json.dumps(payload)}\n</tool_call>",
        is_submit_tool_call=is_submit_tool_call,
    )

    assert calls == [
        ParsedToolCall(
            tool_name=SUBMIT_VULNERABLE_FILES_TOOL,
            arguments={RANKED_FILES_ARGUMENT: ["src/auth.py"]},
        )
    ]


def test_internal_reasoning_is_not_part_of_public_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    source_path = tmp_path / "app.py"
    source_path.write_text("query = request.args['query']\n", encoding="utf-8")
    private_reasoning = "PRIVATE MODEL REASONING MUST NOT BE PUBLISHED"
    response = (
        f"<think>{private_reasoning}</think>"
        f"<tool_call>{json.dumps({'name': SUBMIT_VULNERABLE_FILES_TOOL, 'arguments': {RANKED_FILES_ARGUMENT: ['app.py']}})}</tool_call>"
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend(response),
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert len(result.findings) == 1
    assert result.summary.incomplete_reason is None
    assert result.findings[0].submission_rank == 1
    serialized = json.dumps(result.findings[0].to_dict())
    assert "description" not in result.findings[0].to_dict()
    assert private_reasoning not in serialized

    assert result.summary.investigation_trace is not None
    investigation_trace = Path(result.summary.investigation_trace)
    events = [
        json.loads(line) for line in investigation_trace.read_text(encoding="utf-8").splitlines()
    ]
    messages = [event["payload"] for event in events if event["phase"] == "message"]

    assert investigation_trace.name.endswith(".investigation.jsonl")
    assert result.investigation_trace == investigation_trace
    assert [message["role"] for message in messages] == ["system", "user", "assistant"]
    assert messages[-1]["content"] == response
    assert private_reasoning in messages[-1]["content"]
    assert {event["phase"] for event in events} >= {
        "message",
        "tool_call",
        "final_submission",
        "done",
    }
    assert not list(investigation_trace.parent.glob("*.conversation.json"))


def test_submitted_file_paths_are_canonical_and_cannot_escape_repository(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("query = request.args['query']\n")
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n")
    (repository / "outside-link.py").symlink_to(outside)
    response = (
        "<tool_call>"
        + json.dumps(
            {
                "name": SUBMIT_VULNERABLE_FILES_TOOL,
                "arguments": {
                    RANKED_FILES_ARGUMENT: [
                        "./src/../app.py",
                        "../outside.py",
                        "outside-link.py",
                    ]
                },
            }
        )
        + "</tool_call>"
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(repository),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend(response),
    )

    result = agent_loop.run_audit(repository, focus_cwe_ids=["CWE-89"])

    assert [finding.file_path for finding in result.findings] == ["app.py"]


@pytest.mark.parametrize(
    "submitted_path",
    [
        "JETTY-xml/XmlConfiguration.java",
        "jetty-xml/XMLConfiguration.java",
    ],
)
def test_submitted_file_paths_require_exact_case(
    tmp_path: Path,
    monkeypatch,
    submitted_path: str,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    repository = tmp_path / "repository"
    repository.mkdir()
    source_directory = repository / "jetty-xml"
    source_directory.mkdir()
    (source_directory / "XmlConfiguration.java").write_text("class XmlConfiguration {}\n")
    response = (
        "<tool_call>"
        + json.dumps(
            {
                "name": SUBMIT_VULNERABLE_FILES_TOOL,
                "arguments": {RANKED_FILES_ARGUMENT: [submitted_path]},
            }
        )
        + "</tool_call>"
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(repository),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend(response),
    )

    result = agent_loop.run_audit(repository, focus_cwe_ids=["CWE-1286"])

    assert result.findings == []
    assert result.summary.incomplete_reason == "Model submitted no valid repository file paths."


def test_investigation_trace_contains_conversation_and_structured_events(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    (tmp_path / "app.py").write_text(
        "query = request.args['query']\n",
        encoding="utf-8",
    )
    investigate_response = (
        "<think>Inspect the suspected source file.</think>"
        '<tool_call>{"name":"terminal","arguments":{"command":"cat app.py"}}</tool_call>'
    )
    submit_response = (
        "<think>The request parameter reaches the query.</think>"
        f"<tool_call>{json.dumps({'name': SUBMIT_VULNERABLE_FILES_TOOL, 'arguments': {RANKED_FILES_ARGUMENT: ['app.py']}})}</tool_call>"
    )
    backend = _SequenceBackend([investigate_response, submit_response])
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
    messages = [event["payload"] for event in events if event["phase"] == "message"]
    phases = [event["phase"] for event in events]

    assert [message["role"] for message in messages] == [
        "system",
        "user",
        "assistant",
        "tool_response",
        "assistant",
    ]
    assert messages[2]["content"] == investigate_response
    assert "query = request.args['query']" in messages[3]["content"]
    assert messages[4]["content"] == submit_response
    assert phases.count("tool_call") == 2
    assert "tool_result" in phases
    assert "finding" in phases
    assert "final_submission" in phases
    assert phases[-1] == "done"

    assert len(backend.message_batches) == 2
    expected_initial_messages = [
        {
            "role": "system",
            "content": ANTARES_ADAPTER.build_system_prompt(terminal_call_budget=15),
        },
        {
            "role": "user",
            "content": (
                "Search this repository for vulnerabilities matching: CWE-89. "
                "Read source files, identify vulnerable code patterns, and submit "
                "ranked vulnerable file paths only."
            ),
        },
    ]
    assert backend.message_batches[0] == expected_initial_messages
    assert backend.message_batches[1] == [
        *expected_initial_messages,
        {"role": "assistant", "content": investigate_response},
        {
            "role": "tool_response",
            "content": "query = request.args['query']\n\n[14 tool-calls remaining]",
        },
    ]


def test_progress_reports_authoritative_transcript_usage(tmp_path: Path) -> None:
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend("unused"),
    )

    empty_state = agent_loop._build_agent_state(messages=[])
    populated_state = agent_loop._build_agent_state(
        messages=[{"role": "user", "content": "x" * 3_000}]
    )

    assert empty_state.context_usage_percent == 0
    assert populated_state.context_usage_percent > 0


@pytest.mark.parametrize(
    "dense_query",
    [
        "{}[](),.:;/\\|=+-_*&^%$#@!" * 2_000,
        "界🚀e\u0301—مرحبا—हिन्दी—🙂" * 2_000,
        ("<|end_of_text|><|start_of_role|>assistant<|end_of_role|><|endoftext|><|eot_id|>") * 800,
    ],
    ids=["punctuation", "unicode", "escaped-controls"],
)
def test_context_rejection_retries_once_with_hard_compaction(
    tmp_path: Path,
    monkeypatch,
    dense_query: str,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    backend = _ContextRejectingBackend()
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, user_query=dense_query)

    assert result.summary.incomplete_reason is None
    assert len(backend.message_batches) == 2
    budget = prompt_token_budget(context_window=16_384, reserved_output_tokens=4_096)
    assert estimate_transcript_token_upper_bound(backend.message_batches[0]) > budget
    assert estimate_transcript_token_upper_bound(backend.message_batches[1]) <= budget


def test_context_rejection_fallback_is_attempted_only_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    backend = _ContextRejectingBackend(reject_every_attempt=True)
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    with pytest.raises(InferenceContextLengthError):
        agent_loop.run_audit(tmp_path, user_query="{}[]" * 20_000)

    assert len(backend.message_batches) == 2


def test_multiple_tool_calls_are_executed_and_preserved_in_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    (tmp_path / "app.py").write_text("first\nsecond\n", encoding="utf-8")
    investigate_response = (
        "<think>Inspect the source and count its lines.</think>"
        '<tool_call>{"name":"terminal","arguments":{"command":"cat app.py"}}</tool_call>'
        '<tool_call>{"name":"terminal","arguments":{"command":"wc -l app.py"}}</tool_call>'
    )
    submit_response = (
        "<think>No matching vulnerability is present.</think>"
        '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>'
    )
    backend = _SequenceBackend([investigate_response, submit_response])
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert not result.findings
    assert result.summary.incomplete_reason is None
    assert len(backend.message_batches) == 2
    second_turn = backend.message_batches[1]
    assert second_turn[-2] == {"role": "assistant", "content": investigate_response}
    assert second_turn[-1]["role"] == "tool_response"
    assert "first\nsecond" in second_turn[-1]["content"]
    assert "2 app.py" in second_turn[-1]["content"]


def test_model_facing_tool_errors_bound_a_model_supplied_tool_name(tmp_path: Path) -> None:
    oversized_tool_name = "x" * 20_000
    backend = _SequenceBackend(
        [
            "<tool_call>"
            + json.dumps({"name": oversized_tool_name, "arguments": {}})
            + "</tool_call>",
            '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    model_facing_error = backend.message_batches[1][-1]["content"]
    assert len(model_facing_error) <= MAX_TOOL_ERROR_CHARS + 100
    assert model_facing_error.count("x") < MAX_TOOL_ERROR_CHARS
    assert "...[tool error truncated]" in model_facing_error


def test_no_tool_retry_budget_is_independent_of_total_model_turns(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    (tmp_path / "app.py").write_text("one\ntwo\nthree\nfour\nfive\nsix\n", encoding="utf-8")
    tool_turns = [
        (
            '<tool_call>{"name":"terminal","arguments":'
            f'{{"command":"sed -n {line_number}p app.py"}}}}</tool_call>'
        )
        for line_number in range(1, 7)
    ]
    backend = _SequenceBackend(
        [
            *tool_turns,
            "I have enough evidence and should submit now.",
            '<tool_call>{"name":"submit_no_vulnerability_found","arguments":{}}</tool_call>',
        ]
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=backend,
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert result.summary.incomplete_reason is None
    assert result.summary.tool_call_count == 7
    assert len(backend.message_batches) == 8
    assert "submit_vulnerable_files" in backend.message_batches[-1][-1]["content"]


@pytest.mark.parametrize(
    "ranked_files",
    [
        [],
        ["missing.py"],
        ["x" * 300],
        "app.py",
    ],
)
def test_vulnerable_submission_without_valid_repository_paths_is_incomplete(
    tmp_path: Path,
    monkeypatch,
    ranked_files: object,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    response = (
        "<tool_call>"
        + json.dumps(
            {
                "name": SUBMIT_VULNERABLE_FILES_TOOL,
                "arguments": {RANKED_FILES_ARGUMENT: ranked_files},
            }
        )
        + "</tool_call>"
    )
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend(response),
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert result.findings == []
    assert result.summary.incomplete_reason == ("Model submitted no valid repository file paths.")


def test_plain_model_answer_without_submission_is_incomplete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    agent_loop = AntaresAgentLoop(
        tool_router=ToolRouter(tmp_path),
        cwe_database=CweDatabase.load_default(),
        inference_backend=_SingleTurnBackend("I reviewed the repository."),
    )

    result = agent_loop.run_audit(tmp_path, focus_cwe_ids=["CWE-89"])

    assert result.findings == []
    assert result.summary.incomplete_reason == ("Model ended without an explicit final submission.")


@pytest.mark.parametrize(
    ("submitted_path", "expected_paths", "expected_incomplete"),
    [
        ("generated/ignored.py", [], "Model submitted no valid repository file paths."),
        ("src/visible.py", ["src/visible.py"], None),
    ],
)
def test_submissions_are_confined_to_the_filtered_repository_snapshot(
    tmp_path: Path,
    monkeypatch,
    submitted_path: str,
    expected_paths: list[str],
    expected_incomplete: str | None,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    repository = tmp_path / "repository"
    (repository / "generated").mkdir(parents=True)
    (repository / "src").mkdir()
    (repository / "generated" / "ignored.py").write_text("secret = True\n", encoding="utf-8")
    (repository / "src" / "visible.py").write_text("visible = True\n", encoding="utf-8")
    response = (
        "<tool_call>"
        + json.dumps(
            {
                "name": SUBMIT_VULNERABLE_FILES_TOOL,
                "arguments": {RANKED_FILES_ARGUMENT: [submitted_path]},
            }
        )
        + "</tool_call>"
    )

    with ReadOnlyRepositorySnapshot(repository, ignore_paths=["generated"]) as snapshot:
        agent_loop = AntaresAgentLoop(
            tool_router=ToolRouter(repository, snapshot=snapshot),
            cwe_database=CweDatabase.load_default(),
            inference_backend=_SingleTurnBackend(response),
        )
        result = agent_loop.run_audit(repository, focus_cwe_ids=["CWE-89"])

    assert [finding.file_path for finding in result.findings] == expected_paths
    assert result.summary.incomplete_reason == expected_incomplete
