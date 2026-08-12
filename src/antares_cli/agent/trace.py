# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Session trace writer for JSONL-based audit trails."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from types import TracebackType
from typing import IO, Any

from antares_cli.config import resolve_data_root

_ERROR_TRACE_ATTRIBUTE = "_antares_investigation_trace"


def attach_investigation_trace(error: BaseException, trace_path: Path) -> None:
    """Attach private trace provenance without changing the exception type."""
    setattr(error, _ERROR_TRACE_ATTRIBUTE, trace_path)


def investigation_trace_from_error(error: BaseException) -> Path | None:
    """Return trace provenance attached while unwinding an agent failure."""
    trace_path = getattr(error, _ERROR_TRACE_ATTRIBUTE, None)
    return trace_path if isinstance(trace_path, Path) else None


class SessionTrace:
    def __init__(
        self,
        session_name: str,
        trace_directory: Path | None = None,
    ) -> None:
        sanitized_name = re.sub(r"[^\w\-]", "_", session_name)
        resolved_directory = trace_directory or resolve_data_root() / "traces"
        resolved_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved_directory.chmod(0o700)
        unique_suffix = uuid.uuid4().hex[:8]
        self._trace_path: Path = (
            resolved_directory
            / f"{sanitized_name}-{int(time.time() * 1000)}-{unique_suffix}.investigation.jsonl"
        )
        self._file_handle: IO[str] | None = None

    @staticmethod
    def new_evidence_id() -> str:
        """Return a compact identifier for cross-referencing trace evidence."""
        return uuid.uuid4().hex[:12]

    def _ensure_open(self) -> IO[str]:
        if self._file_handle is None or self._file_handle.closed:
            file_descriptor = os.open(
                self._trace_path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
            self._file_handle = os.fdopen(file_descriptor, "a", encoding="utf-8")
        return self._file_handle

    def record_event(
        self,
        phase: str,
        payload: dict[str, Any],
        evidence_id: str | None = None,
    ) -> None:
        handle = self._ensure_open()
        event = {
            "timestamp": time.time(),
            "phase": phase,
            "payload": payload,
            "evidence_id": evidence_id,
        }
        handle.write(json.dumps(event) + "\n")
        handle.flush()

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        evidence_id: str | None = None,
    ) -> None:
        self.record_event(
            phase="tool_call",
            payload={"tool_name": tool_name, "arguments": arguments},
            evidence_id=evidence_id,
        )

    def record_tool_result(
        self,
        tool_name: str,
        result_summary: str,
        evidence_id: str,
    ) -> None:
        self.record_event(
            phase="tool_result",
            payload={"tool_name": tool_name, "result_summary": result_summary},
            evidence_id=evidence_id,
        )

    def record_finding(self, finding_dict: dict[str, Any], evidence_id: str) -> None:
        self.record_event(
            phase="finding",
            payload=finding_dict,
            evidence_id=evidence_id,
        )

    def record_message(
        self,
        message: dict[str, Any],
        *,
        attempt: int | None = None,
        parse_error: bool = False,
        generation_error: bool = False,
    ) -> None:
        """Append one model-conversation message to the canonical investigation trace."""
        payload = dict(message)
        if attempt is not None:
            payload["attempt"] = attempt
        if parse_error:
            payload["parse_error"] = True
        if generation_error:
            payload["generation_error"] = True
        self.record_event(
            phase="message",
            payload=payload,
        )

    def finalize(self, summary_dict: dict[str, Any]) -> Path:
        self.record_event(phase="done", payload=summary_dict)
        self.close()
        return self._trace_path

    def finalize_error(self, error: BaseException) -> Path:
        """Record a bounded failure event and close the trace."""
        error_type = type(error).__name__
        self.record_event(
            phase="error",
            payload={"type": error_type, "message": str(error)[:1_000]},
        )
        return self.finalize({"status": "failed", "error_type": error_type})

    def close(self) -> None:
        if self._file_handle is not None and not self._file_handle.closed:
            self._file_handle.close()

    def __enter__(self) -> SessionTrace:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        self.close()
