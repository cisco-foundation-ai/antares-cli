# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Persistent run provenance and history for Antares CLI executions."""

from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from antares_cli import __version__
from antares_cli.agent.trace import investigation_trace_from_error
from antares_cli.config import resolve_data_root
from antares_cli.core.service import WorkflowResult

_SECRET_OPTION_NAMES = {
    "--api-key",
    "--endpoint",
    "--token",
    "--password",
    "--secret",
}
_SECRET_RECORD_KEYS = {
    "api_key",
    "authorization",
    "password",
    "secret",
    "token",
}
_SAFE_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_TRACE_BYTES = 50 * 1024 * 1024
_MAX_EXPORTED_TRACE_BYTES = 10 * 1024 * 1024
_REDACTED_TRACE_CONTENT = "<redacted from portable export>"
_LOCK_TIMEOUT_SECONDS = 5.0
_STALE_LOCK_SECONDS = 30.0


@dataclass(slots=True, frozen=True)
class InvocationContext:
    execution_id: str
    started_at: str
    argv: list[str]
    command: str
    cwd: str
    executable: str
    antares_version: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class GitSnapshot:
    repository_root: str | None
    commit: str | None
    branch: str | None
    remote_url: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def capture_invocation(
    *,
    argv: list[str] | None = None,
    cwd: Path | None = None,
) -> InvocationContext:
    redacted_argv = _redact_argv(list(sys.argv if argv is None else argv))
    return InvocationContext(
        execution_id=uuid.uuid4().hex[:12],
        started_at=_utc_now(),
        argv=redacted_argv,
        command=shlex.join(redacted_argv),
        cwd=str((cwd or Path.cwd()).resolve()),
        executable=sys.executable,
        antares_version=__version__,
    )


def record_workflow_run(
    result: WorkflowResult,
    *,
    invocation: InvocationContext,
    target: Path,
    output_path: Path | None = None,
    status: str = "completed",
) -> dict[str, object]:
    investigation_traces = _investigation_traces_from_result(result)
    execution = _execution_metadata(
        invocation=invocation,
        target=target,
        investigation_traces=investigation_traces,
    )
    reproducibility = result.metadata.get("reproducibility")
    record = _base_run_record(
        invocation=invocation,
        status=status,
        target=target,
        metadata=result.metadata,
        execution=execution,
    )
    record["request_id"] = result.metadata.get("request_id")
    record["request_hash"] = (
        reproducibility.get("request_hash") if isinstance(reproducibility, dict) else None
    )
    record["summary"] = result.summary.to_dict()
    record["per_cwe_results"] = result.per_cwe_results
    record["investigation_traces"] = investigation_traces
    record["output_path"] = str(output_path.resolve()) if output_path is not None else None
    _finalize_run_record(record, investigation_traces=investigation_traces)
    return record


def record_failed_run(
    *,
    invocation: InvocationContext,
    mode: str,
    target: Path,
    error: Exception,
    request_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata = dict(request_metadata or {})
    metadata.setdefault("mode", mode)
    investigation_trace = investigation_trace_from_error(error)
    investigation_traces = [str(investigation_trace)] if investigation_trace is not None else []
    execution = _execution_metadata(
        invocation=invocation,
        target=target,
        investigation_traces=investigation_traces,
    )
    record = _base_run_record(
        invocation=invocation,
        status="failed",
        target=target,
        metadata=metadata,
        execution=execution,
    )
    record["request_id"] = None
    record["request_hash"] = None
    record["summary"] = {}
    record["investigation_traces"] = investigation_traces
    record["output_path"] = None
    record["error"] = {"type": type(error).__name__, "message": str(error)}
    _finalize_run_record(record, investigation_traces=investigation_traces)
    return record


def _base_run_record(
    *,
    invocation: InvocationContext,
    status: str,
    target: Path,
    metadata: dict[str, object],
    execution: dict[str, object],
) -> dict[str, object]:
    return {
        "execution_id": invocation.execution_id,
        "status": status,
        "recorded_at": _utc_now(),
        "invocation": invocation.to_dict(),
        "mode": metadata.get("mode"),
        "target": str(target.resolve()),
        "model": metadata.get("model"),
        "backend": metadata.get("backend"),
        "profile": metadata.get("profile"),
        "cwe_ids": metadata.get("cwe_ids", []),
        "query": metadata.get("query"),
        "model_configuration": metadata.get("model_configuration"),
        "target_git": execution.get("target_git"),
        "antares_git": execution.get("antares_git"),
    }


def load_run_records(*, limit: int | None = None) -> list[dict[str, object]]:
    index_path = runs_index_path()
    if not index_path.exists():
        return []
    if limit is not None and limit < 1:
        return []
    records: list[dict[str, object]] | deque[dict[str, object]]
    records = deque(maxlen=limit) if limit is not None else []
    for record in _iter_run_records(index_path):
        records.append(record)
    return list(reversed(records))


def _iter_run_records(index_path: Path) -> Iterator[dict[str, object]]:
    with index_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                yield parsed


def find_run_record(run_id_prefix: str) -> dict[str, object]:
    index_path = runs_index_path()
    matches: list[dict[str, object]] = []
    if index_path.exists():
        for record in _iter_run_records(index_path):
            if not str(record.get("execution_id", "")).startswith(run_id_prefix):
                continue
            matches.append(record)
            if len(matches) == 2:
                break
    if not matches:
        raise ValueError(f"No Antares run found for id prefix: {run_id_prefix}")
    if len(matches) > 1:
        matching_ids = ", ".join(str(record.get("execution_id")) for record in matches)
        raise ValueError(f"Run id prefix is ambiguous: {matching_ids}")
    return matches[0]


def export_run_bundle(record: dict[str, object], output_path: Path) -> Path:
    execution_id = _validated_execution_id(record.get("execution_id", "run"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=f".{output_path.name}-",
        suffix=".tmp",
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    try:
        temporary_path.chmod(0o600)
        with tarfile.open(temporary_path, "w:gz") as tar:
            export_record = _sanitize_export_record(record)
            export_record["trace_export_policy"] = "message and tool content redacted"
            manifest_bytes = json.dumps(export_record, indent=2, sort_keys=True).encode()
            info = tarfile.TarInfo(name=f"{execution_id}/manifest.json")
            info.size = len(manifest_bytes)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(manifest_bytes))
            for investigation_trace in _investigation_traces_from_record(record):
                trace_path = resolve_investigation_trace(investigation_trace)
                trace_bytes = _sanitized_trace_bytes(trace_path)
                trace_info = tarfile.TarInfo(name=f"{execution_id}/traces/{trace_path.name}")
                trace_info.size = len(trace_bytes)
                trace_info.mode = 0o600
                tar.addfile(trace_info, io.BytesIO(trace_bytes))
        os.replace(temporary_path, output_path)
        output_path.chmod(0o600)
    finally:
        temporary_path.unlink(missing_ok=True)
    return output_path


def export_run_bundles(
    records: list[dict[str, object]],
    output_dir: Path,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return [
        export_run_bundle(
            record,
            output_dir / f"{_validated_execution_id(record.get('execution_id', 'run'))}.tar.gz",
        )
        for record in records
    ]


def resolve_investigation_trace(raw_path: object) -> Path:
    """Resolve a regular trace file confined beneath the private trace directory."""
    candidate = Path(str(raw_path))
    if candidate.is_symlink():
        raise ValueError(f"Investigation trace cannot be a symlink: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(f"Investigation trace does not exist: {candidate}") from error
    trace_root = (resolve_data_root() / "traces").resolve()
    try:
        resolved.relative_to(trace_root)
    except ValueError as error:
        raise ValueError(
            f"Investigation trace is outside the Antares trace directory: {candidate}"
        ) from error
    if not resolved.is_file():
        raise ValueError(f"Investigation trace is not a regular file: {candidate}")
    if resolved.stat().st_size > _MAX_TRACE_BYTES:
        raise ValueError(f"Investigation trace exceeds the {_MAX_TRACE_BYTES:,}-byte limit")
    return resolved


def _validated_execution_id(raw_execution_id: object) -> str:
    execution_id = str(raw_execution_id)
    if not _SAFE_EXECUTION_ID.fullmatch(execution_id):
        raise ValueError("Run execution id contains unsafe path characters")
    return execution_id


def _sanitized_trace_bytes(trace_path: Path) -> bytes:
    exported = bytearray()
    with trace_path.open(encoding="utf-8") as trace_file:
        for line in trace_file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            encoded = json.dumps(_sanitize_trace_event(event), sort_keys=True).encode() + b"\n"
            if len(exported) + len(encoded) > _MAX_EXPORTED_TRACE_BYTES:
                raise ValueError(
                    f"Sanitized trace exceeds the {_MAX_EXPORTED_TRACE_BYTES:,}-byte export limit"
                )
            exported.extend(encoded)
    return bytes(exported)


def _sanitize_trace_event(event: dict[str, object]) -> dict[str, object]:
    sanitized = dict(event)
    phase = sanitized.get("phase")
    payload = sanitized.get("payload")
    if not isinstance(payload, dict):
        return sanitized
    if phase == "message":
        sanitized["payload"] = {
            key: (_REDACTED_TRACE_CONTENT if key == "content" else value)
            for key, value in payload.items()
        }
    elif phase == "tool_call":
        sanitized["payload"] = {
            **payload,
            "arguments": _REDACTED_TRACE_CONTENT,
        }
    elif phase == "tool_result":
        sanitized["payload"] = {
            **payload,
            "result_summary": _REDACTED_TRACE_CONTENT,
        }
    elif phase == "ingest":
        sanitized["payload"] = {
            **payload,
            "path": _REDACTED_TRACE_CONTENT,
            "query": _REDACTED_TRACE_CONTENT,
        }
    elif phase == "quarantine_alert":
        sanitized["payload"] = {
            **payload,
            "source": _REDACTED_TRACE_CONTENT,
        }
    else:
        sanitized["payload"] = _sanitize_export_value(payload)
    return sanitized


def _investigation_traces_from_record(record: dict[str, object]) -> list[str]:
    raw = record.get("investigation_traces")
    if not isinstance(raw, list):
        raw = record.get("trace_files")
    if not isinstance(raw, list):
        return []
    return [str(entry) for entry in raw if isinstance(entry, str) and entry]


def runs_directory() -> Path:
    directory = resolve_data_root() / "runs"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    return directory


def runs_index_path() -> Path:
    return runs_directory() / "runs.jsonl"


def capture_git_snapshot(path: Path) -> GitSnapshot:
    cwd = path if path.is_dir() else path.parent
    git_marker = _nearest_git_marker(cwd.resolve())
    if git_marker is None:
        return _empty_git_snapshot()
    try:
        marker_mode = git_marker.lstat().st_mode
    except OSError:
        return _empty_git_snapshot()
    if not stat.S_ISDIR(marker_mode):
        return _empty_git_snapshot()
    root = _run_git(["rev-parse", "--show-toplevel"], cwd=cwd)
    if root is None:
        return _empty_git_snapshot()
    root_path = Path(root)
    return GitSnapshot(
        repository_root=str(root_path),
        commit=_run_git(["rev-parse", "HEAD"], cwd=root_path),
        branch=_run_git(["branch", "--show-current"], cwd=root_path),
        remote_url=_sanitize_git_remote_url(
            _run_git(["remote", "get-url", "origin"], cwd=root_path)
        ),
    )


def _nearest_git_marker(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        marker = directory / ".git"
        try:
            marker.lstat()
        except FileNotFoundError:
            continue
        return marker
    return None


def _empty_git_snapshot() -> GitSnapshot:
    return GitSnapshot(
        repository_root=None,
        commit=None,
        branch=None,
        remote_url=None,
    )


def _execution_metadata(
    *,
    invocation: InvocationContext,
    target: Path,
    investigation_traces: list[str],
) -> dict[str, object]:
    return {
        "execution_id": invocation.execution_id,
        "started_at": invocation.started_at,
        "command": invocation.command,
        "argv": invocation.argv,
        "cwd": invocation.cwd,
        "executable": invocation.executable,
        "antares_version": invocation.antares_version,
        "investigation_traces": investigation_traces,
        "target_git": capture_git_snapshot(target).to_dict(),
        "antares_git": capture_git_snapshot(Path(__file__)).to_dict(),
    }


def _investigation_traces_from_result(result: WorkflowResult) -> list[str]:
    investigation_traces: list[str] = []
    if result.summary.investigation_trace:
        investigation_traces.append(result.summary.investigation_trace)
    for entry in result.per_cwe_results:
        investigation_trace = entry.get("investigation_trace")
        if isinstance(investigation_trace, str) and investigation_trace:
            investigation_traces.append(investigation_trace)
    return sorted(dict.fromkeys(investigation_traces))


def _append_run_record(record: dict[str, object]) -> None:
    index_path = runs_index_path()
    encoded = (json.dumps(record, sort_keys=True) + "\n").encode()
    with _exclusive_index_lock(index_path.with_suffix(".lock")):
        file_descriptor = os.open(
            index_path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            _write_all(file_descriptor, encoded)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)


def _write_run_manifest(record: dict[str, object]) -> None:
    execution_id = _validated_execution_id(record["execution_id"])
    manifest_path = runs_directory() / f"{execution_id}.json"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=manifest_path.parent,
            prefix=f".{execution_id}-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(json.dumps(record, indent=2, sort_keys=True))
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        temporary_path.chmod(0o600)
        os.replace(temporary_path, manifest_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@contextmanager
def _exclusive_index_lock(lock_path: Path) -> Iterator[None]:
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    token = uuid.uuid4().hex.encode()
    file_descriptor: int | None = None
    while file_descriptor is None:
        try:
            file_descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            _write_all(file_descriptor, token)
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > _STALE_LOCK_SECONDS:
                    lock_path.unlink()
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting to update the Antares run index") from None
            time.sleep(0.01)
    try:
        yield
    finally:
        os.close(file_descriptor)
        try:
            if lock_path.read_bytes() == token:
                lock_path.unlink()
        except FileNotFoundError:
            pass


def _write_all(file_descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(file_descriptor, remaining)
        if written == 0:
            raise OSError("Unable to persist Antares run data")
        remaining = remaining[written:]


def _finalize_run_record(
    record: dict[str, object],
    *,
    investigation_traces: list[str],
) -> None:
    if investigation_traces:
        _append_trace_provenance(investigation_traces, record)
    _write_run_manifest(record)
    _append_run_record(record)


def _append_trace_provenance(
    investigation_traces: list[str],
    record: dict[str, object],
) -> None:
    event = {
        "timestamp": time.time(),
        "phase": "run_provenance",
        "payload": record,
        "evidence_id": None,
    }
    encoded = json.dumps(event, sort_keys=True) + "\n"
    for investigation_trace in investigation_traces:
        trace_path = resolve_investigation_trace(investigation_trace)
        with trace_path.open("a", encoding="utf-8") as handle:
            handle.write(encoded)


def _run_git(
    args: list[str],
    *,
    cwd: Path,
) -> str | None:
    git_executable = shutil.which("git", path=os.defpath)
    if git_executable is None:
        return None
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        completed = subprocess.run(
            [
                git_executable,
                "-c",
                "color.ui=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "credential.helper=",
                *args,
            ],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
        elif arg in _SECRET_OPTION_NAMES:
            redacted.append(arg)
            skip_next = True
        elif "=" in arg and arg.partition("=")[0] in _SECRET_OPTION_NAMES:
            redacted.append(f"{arg.partition('=')[0]}=<redacted>")
        else:
            redacted.append(arg)
    return redacted


def _sanitize_export_record(record: dict[str, object]) -> dict[str, object]:
    sanitized = _sanitize_export_value(record)
    if not isinstance(sanitized, dict):
        raise TypeError("Sanitized run record must remain an object")
    original_invocation = record.get("invocation")
    sanitized_invocation = sanitized.get("invocation")
    if isinstance(original_invocation, dict) and isinstance(sanitized_invocation, dict):
        raw_argv = original_invocation.get("argv")
        if isinstance(raw_argv, list) and all(isinstance(item, str) for item in raw_argv):
            redacted_argv = _redact_argv(raw_argv)
        else:
            raw_command = original_invocation.get("command")
            try:
                parsed_command = shlex.split(raw_command) if isinstance(raw_command, str) else []
            except ValueError:
                parsed_command = []
            redacted_argv = _redact_argv(parsed_command)
        sanitized_invocation["argv"] = redacted_argv
        sanitized_invocation["command"] = shlex.join(redacted_argv)
    return sanitized


def _sanitize_export_value(value: object, *, key: str | None = None) -> object:
    normalized_key = key.lower() if key is not None else None
    if normalized_key in _SECRET_RECORD_KEYS and value is not None:
        return "<redacted>"
    if normalized_key == "endpoint" and value:
        return "<configured>"
    if normalized_key == "remote_url" and isinstance(value, str):
        return _sanitize_git_remote_url(value)
    if isinstance(value, dict):
        return {
            str(nested_key): _sanitize_export_value(nested_value, key=str(nested_key))
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_export_value(item) for item in value]
    return value


def _sanitize_git_remote_url(remote_url: str | None) -> str | None:
    if remote_url is None or "://" not in remote_url:
        return remote_url
    try:
        parsed = urlsplit(remote_url)
        hostname = parsed.hostname
        if hostname is None:
            return None
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except ValueError:
        return None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
