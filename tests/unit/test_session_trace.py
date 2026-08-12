# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JSONL session trace writer."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from antares_cli.agent.trace import SessionTrace


def test_investigation_trace_created_on_first_event(tmp_path: Path) -> None:
    trace = SessionTrace("test-session", trace_directory=tmp_path)
    trace.record_event("start", {"repo": "example"})

    jsonl_files = list(tmp_path.glob("*.investigation.jsonl"))
    assert len(jsonl_files) == 1
    trace.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_trace_directory_and_file_are_private(tmp_path: Path) -> None:
    trace_directory = tmp_path / "traces"
    trace = SessionTrace("test-session", trace_directory=trace_directory)
    trace.record_event("start", {"repo": "example"})
    trace.close()

    trace_path = next(trace_directory.glob("*.investigation.jsonl"))
    assert stat.S_IMODE(trace_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(trace_path.stat().st_mode) == 0o600


def test_events_written_as_valid_jsonl(tmp_path: Path) -> None:
    trace = SessionTrace("test-session", trace_directory=tmp_path)
    trace.record_event("phase_a", {"key": "value_a"})
    trace.record_event("phase_b", {"key": "value_b"})
    trace.record_event("phase_c", {"key": "value_c"})
    trace.close()

    jsonl_file = next(tmp_path.glob("*.investigation.jsonl"))
    lines = jsonl_file.read_text().strip().splitlines()
    assert len(lines) == 3
    for line in lines:
        parsed = json.loads(line)
        assert "timestamp" in parsed
        assert "phase" in parsed
        assert "payload" in parsed


def test_finalize_writes_done_and_returns_path(tmp_path: Path) -> None:
    trace = SessionTrace("test-session", trace_directory=tmp_path)
    trace.record_event("start", {"repo": "example"})
    returned_path = trace.finalize({"total_findings": 5})

    assert returned_path.exists()
    lines = returned_path.read_text().strip().splitlines()
    last_event = json.loads(lines[-1])
    assert last_event["phase"] == "done"
    assert last_event["payload"]["total_findings"] == 5


def test_messages_are_appended_as_typed_events(tmp_path: Path) -> None:
    trace = SessionTrace("test-session", trace_directory=tmp_path)
    trace.record_message(
        {"role": "assistant", "content": "I found the vulnerable file."},
        attempt=2,
    )
    trace.close()

    trace_path = next(tmp_path.glob("*.investigation.jsonl"))
    event = json.loads(trace_path.read_text(encoding="utf-8"))

    assert event["phase"] == "message"
    assert event["payload"] == {
        "role": "assistant",
        "content": "I found the vulnerable file.",
        "attempt": 2,
    }


def test_evidence_cross_references_preserved(tmp_path: Path) -> None:
    trace = SessionTrace("test-session", trace_directory=tmp_path)
    trace.record_tool_result("search_code", "3 matches", evidence_id="abc123def456")
    trace.close()

    jsonl_file = next(tmp_path.glob("*.investigation.jsonl"))
    parsed = json.loads(jsonl_file.read_text().strip())
    assert parsed["evidence_id"] == "abc123def456"


def test_generated_evidence_ids_are_compact_unique_hex() -> None:
    evidence_ids = {SessionTrace.new_evidence_id() for _ in range(10)}

    assert len(evidence_ids) == 10
    assert all(len(evidence_id) == 12 for evidence_id in evidence_ids)
    assert all(int(evidence_id, 16) >= 0 for evidence_id in evidence_ids)


def test_session_trace_supports_with_statement(tmp_path: Path) -> None:
    with SessionTrace("test-session", trace_directory=tmp_path) as trace:
        trace.record_event("inside", {"status": "ok"})

    jsonl_file = next(tmp_path.glob("*.investigation.jsonl"))
    assert jsonl_file.exists()
    parsed = json.loads(jsonl_file.read_text().strip())
    assert parsed["phase"] == "inside"


def test_session_name_with_path_separators(tmp_path: Path) -> None:
    trace = SessionTrace("a/b/c", trace_directory=tmp_path)
    trace.record_event("start", {"repo": "example"})
    trace.close()

    jsonl_files = list(tmp_path.glob("*.investigation.jsonl"))
    assert len(jsonl_files) == 1
    assert "a_b_c" in jsonl_files[0].name
