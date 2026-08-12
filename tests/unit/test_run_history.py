# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for run provenance capture and history storage."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from antares_cli.core.service import WorkflowResult
from antares_cli.output.finding import ReportSummary
from antares_cli.run_history import (
    _append_run_record,
    _sanitize_git_remote_url,
    capture_git_snapshot,
    capture_invocation,
    export_run_bundle,
    find_run_record,
    load_run_records,
    record_workflow_run,
    runs_index_path,
)


def test_capture_invocation_redacts_secret_option_values() -> None:
    invocation = capture_invocation(
        argv=[
            "antares",
            "query",
            ".",
            "--api-key",
            "sk-secret",
            "--token=abc123",
            "--endpoint",
            "https://private.example.test/path-token",
            "--endpoint=https://other-private.example.test/secret",
        ],
        cwd=Path.cwd(),
    )

    assert invocation.argv == [
        "antares",
        "query",
        ".",
        "--api-key",
        "<redacted>",
        "--token=<redacted>",
        "--endpoint",
        "<redacted>",
        "--endpoint=<redacted>",
    ]
    assert "sk-secret" not in invocation.command
    assert "abc123" not in invocation.command
    assert "private.example.test" not in invocation.command


def test_git_remote_url_removes_credentials_query_and_fragment() -> None:
    remote = "https://x-access-token:secret@github.com/example/project.git?token=other#fragment"

    assert _sanitize_git_remote_url(remote) == "https://github.com/example/project.git"


def test_git_snapshot_does_not_execute_repository_fsmonitor_hook(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    marker = tmp_path / "fsmonitor-executed"
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o700)
    subprocess.run(
        ["git", "config", "core.fsmonitor", str(hook)],
        cwd=repository,
        check=True,
    )

    snapshot = capture_git_snapshot(repository)

    assert snapshot.repository_root == str(repository)
    assert not marker.exists()


def test_git_snapshot_ignores_inherited_git_config_injection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    marker = tmp_path / "injected-fsmonitor-executed"
    hook = tmp_path / "injected-fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o700)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hook))

    capture_git_snapshot(repository)

    assert not marker.exists()


def test_git_snapshot_does_not_execute_repository_clean_filters(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.test"],
        cwd=repository,
        check=True,
    )
    (repository / ".gitattributes").write_text("victim.txt filter=pwn\n", encoding="utf-8")
    victim = repository / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repository, check=True)
    marker = tmp_path / "clean-filter-executed"
    subprocess.run(
        ["git", "config", "filter.pwn.clean", f'sh -c "touch {marker}; cat"'],
        cwd=repository,
        check=True,
    )
    victim.write_text("modified\n", encoding="utf-8")

    snapshot = capture_git_snapshot(repository)

    assert snapshot.commit is not None
    assert not marker.exists()


def test_git_snapshot_does_not_follow_external_gitfile(tmp_path: Path) -> None:
    private_repository = tmp_path / "private-repository"
    private_repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=private_repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://private.example.test/secret.git"],
        cwd=private_repository,
        check=True,
    )
    hostile_target = tmp_path / "hostile-target"
    hostile_target.mkdir()
    (hostile_target / ".git").write_text(
        f"gitdir: {private_repository / '.git'}\n",
        encoding="utf-8",
    )

    snapshot = capture_git_snapshot(hostile_target)

    assert snapshot == type(snapshot)(
        repository_root=None,
        commit=None,
        branch=None,
        remote_url=None,
    )


def test_scp_style_git_remote_is_preserved() -> None:
    assert _sanitize_git_remote_url("git@github.com:example/project.git") == (
        "git@github.com:example/project.git"
    )


def test_load_run_records_ignores_missing_index(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))

    assert load_run_records() == []


def test_concurrent_run_index_appends_remain_valid_jsonl(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(
            executor.map(
                _append_run_record,
                ({"execution_id": f"run-{index:03}"} for index in range(40)),
            )
        )

    records = load_run_records()
    assert len(records) == 40
    assert {record["execution_id"] for record in records} == {
        f"run-{index:03}" for index in range(40)
    }


def test_find_run_record_resolves_unique_prefix(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    index_path = runs_index_path()
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(
        json.dumps({"execution_id": "abcdef123456"}) + "\n",
        encoding="utf-8",
    )

    assert find_run_record("abcdef")["execution_id"] == "abcdef123456"


def test_record_workflow_run_writes_local_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    target_path = tmp_path / "app.py"
    target_path.write_text("print('hello')\n", encoding="utf-8")
    investigation_trace = tmp_path / "antares-data" / "traces" / "run.investigation.jsonl"
    investigation_trace.parent.mkdir(parents=True)
    investigation_trace.write_text(
        json.dumps({"phase": "done", "payload": {}}) + "\n",
        encoding="utf-8",
    )
    invocation = capture_invocation(argv=["antares", "query", "."], cwd=tmp_path)
    result = _workflow_result(investigation_trace=str(investigation_trace))

    record = record_workflow_run(result, invocation=invocation, target=target_path)

    assert "execution" not in result.metadata
    assert "execution_id" not in result.metadata
    assert record["execution_id"] == invocation.execution_id
    assert record["investigation_traces"] == [str(investigation_trace)]
    assert "trace_files" not in record
    assert record["summary"]["investigation_trace"] == str(investigation_trace)
    assert (tmp_path / "antares-data" / "runs" / f"{invocation.execution_id}.json").exists()
    assert load_run_records()[0]["execution_id"] == invocation.execution_id


def test_export_bundle_contains_one_canonical_investigation_trace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    investigation_trace = tmp_path / "antares-data" / "traces" / "run.investigation.jsonl"
    investigation_trace.parent.mkdir(parents=True)
    investigation_trace.write_text(
        json.dumps({"phase": "message", "payload": {"role": "assistant"}}) + "\n",
        encoding="utf-8",
    )
    bundle_path = tmp_path / "run.tar.gz"

    export_run_bundle(
        {
            "execution_id": "run-123",
            "investigation_traces": [str(investigation_trace)],
        },
        bundle_path,
    )

    with tarfile.open(bundle_path, "r:gz") as bundle:
        names = bundle.getnames()

    assert names == [
        "run-123/manifest.json",
        "run-123/traces/run.investigation.jsonl",
    ]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_export_bundle_is_private_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    bundle_path = tmp_path / "run.tar.gz"

    export_run_bundle(
        {"execution_id": "run-123", "investigation_traces": []},
        bundle_path,
    )

    assert stat.S_IMODE(bundle_path.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".run.tar.gz-*.tmp")) == []


def test_failed_export_preserves_existing_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    bundle_path = tmp_path / "run.tar.gz"
    original = b"existing bundle"
    bundle_path.write_bytes(original)
    outside_trace = tmp_path / "outside.investigation.jsonl"
    outside_trace.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the Antares trace directory"):
        export_run_bundle(
            {
                "execution_id": "run-123",
                "investigation_traces": [str(outside_trace)],
            },
            bundle_path,
        )

    assert bundle_path.read_bytes() == original
    assert list(tmp_path.glob(".run.tar.gz-*.tmp")) == []


def test_export_bundle_redacts_message_tool_and_ingest_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    trace_path = tmp_path / "antares-data" / "traces" / "run.investigation.jsonl"
    trace_path.parent.mkdir(parents=True)
    secret = "repository-secret-value"
    trace_path.write_text(
        "\n".join(
            [
                json.dumps({"phase": "message", "payload": {"role": "user", "content": secret}}),
                json.dumps(
                    {
                        "phase": "tool_call",
                        "payload": {"tool_name": "terminal", "arguments": {"command": secret}},
                    }
                ),
                json.dumps(
                    {
                        "phase": "tool_result",
                        "payload": {"tool_name": "terminal", "result_summary": secret},
                    }
                ),
                json.dumps(
                    {
                        "phase": "quarantine_alert",
                        "payload": {
                            "source": f"terminal(command=cat {secret})",
                            "count": 1,
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bundle_path = tmp_path / "run.tar.gz"

    export_run_bundle(
        {"execution_id": "run-123", "investigation_traces": [str(trace_path)]},
        bundle_path,
    )

    with tarfile.open(bundle_path, "r:gz") as bundle:
        exported_trace = bundle.extractfile("run-123/traces/run.investigation.jsonl").read()
        manifest = bundle.extractfile("run-123/manifest.json").read()
    assert secret.encode() not in exported_trace
    assert b"redacted from portable export" in exported_trace
    assert b"trace_export_policy" in manifest


def test_export_bundle_rejects_trace_outside_private_trace_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANTARES_DATA_DIR", str(tmp_path / "antares-data"))
    outside = tmp_path / "outside.investigation.jsonl"
    outside.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the Antares trace directory"):
        export_run_bundle(
            {"execution_id": "run-123", "investigation_traces": [str(outside)]},
            tmp_path / "run.tar.gz",
        )


def test_export_bundle_sanitizes_connection_credentials(tmp_path: Path) -> None:
    bundle_path = tmp_path / "run.tar.gz"
    record = {
        "execution_id": "run-123",
        "investigation_traces": [],
        "target_git": {"remote_url": "https://token:secret@github.com/example/project.git"},
        "model_configuration": {
            "settings": {
                "endpoint": "https://private.example.test/v1",
                "api_key": "secret-key",
            }
        },
    }

    export_run_bundle(record, bundle_path)

    with tarfile.open(bundle_path, "r:gz") as bundle:
        manifest = json.loads(bundle.extractfile("run-123/manifest.json").read())
    serialized = json.dumps(manifest)
    assert manifest["target_git"]["remote_url"] == "https://github.com/example/project.git"
    assert manifest["model_configuration"]["settings"]["endpoint"] == "<configured>"
    assert manifest["model_configuration"]["settings"]["api_key"] == "<redacted>"
    assert "private.example.test" not in serialized
    assert "secret-key" not in serialized


@pytest.mark.parametrize(
    "argv",
    [
        ["antares", "query", ".", "--endpoint", "https://private/token/SECRET"],
        ["antares", "query", ".", "--endpoint=https://private/token/SECRET"],
    ],
)
def test_export_bundle_redacts_legacy_invocation_endpoints(
    tmp_path: Path,
    argv: list[str],
) -> None:
    endpoint = "https://private/token/SECRET"
    bundle_path = tmp_path / "legacy.tar.gz"
    record = {
        "execution_id": "legacy-run",
        "investigation_traces": [],
        "invocation": {"argv": argv, "command": " ".join(argv)},
    }

    export_run_bundle(record, bundle_path)

    with tarfile.open(bundle_path, "r:gz") as bundle:
        manifest = json.loads(bundle.extractfile("legacy-run/manifest.json").read())
    serialized = json.dumps(manifest)
    assert endpoint not in serialized
    assert "SECRET" not in serialized
    assert "<redacted>" in serialized


def _workflow_result(*, investigation_trace: str | None = None) -> WorkflowResult:
    summary = ReportSummary(
        total_findings=0,
        tool_call_count=0,
        duration_seconds=0.0,
        investigation_trace=investigation_trace,
        cwe_ids_triggered=[],
    )
    return WorkflowResult(
        findings=[],
        summary=summary,
        metadata={
            "mode": "query",
            "model": "test-model",
            "backend": "remote",
            "profile": None,
            "cwe_ids": ["CWE-89"],
            "query": None,
            "request_id": "request",
            "reproducibility": {"request_hash": "request-hash"},
            "model_configuration": {
                "settings": {"model": "test-model", "backend": "remote"},
                "backend": {"backend_name": "scripted"},
            },
        },
    )
