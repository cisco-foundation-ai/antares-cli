# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository tools must never mutate or escape the analysis target."""

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import pytest

from antares_cli.agent.quarantine import validate_tool_call_safety
from antares_cli.agent.tool_router import (
    MAX_READ_FILE_BYTES,
    MAX_READ_FILE_CHARS,
    MAX_TOOL_ERROR_CHARS,
    ToolRouter,
)
from antares_cli.core.repository_paths import iter_repository_files
from antares_cli.tools.readonly_workspace import ReadOnlyRepositorySnapshot
from antares_cli.tools.shell_exec import MAX_TOOL_OUTPUT_CHARS, run_bash


class _BlockingStream:
    def __init__(self) -> None:
        self.read_started = threading.Event()
        self._closed = threading.Event()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def read(self, _size: int) -> bytes:
        self.read_started.set()
        if not self._closed.wait(timeout=2):
            raise AssertionError("stream was not closed during failed pipeline cleanup")
        raise ValueError("I/O operation on closed file")

    def close(self) -> None:
        self._closed.set()


class _EmptyStream:
    def __init__(self) -> None:
        self.closed = False

    def read(self, _size: int) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


class _ErrorStream(_EmptyStream):
    def read(self, _size: int) -> bytes:
        raise OSError("synthetic pipe read failure")


class _ExitedProcess:
    stdin = None
    returncode = 0

    def __init__(self, stdout: object, stderr: object, *, pid: int) -> None:
        self.pid = pid
        self.stdout = stdout
        self.stderr = stderr

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0


_DESCENDANT_HELPER = """
import os
import signal
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
mode = sys.argv[2]
ready_marker = Path(sys.argv[3])
child_pid = os.fork()
if child_pid == 0:
    if mode == "graceful":
        def stop(_signum, _frame):
            marker.unlink(missing_ok=True)
            os._exit(0)
        signal.signal(signal.SIGTERM, stop)
    else:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    marker.write_text(str(os.getpid()), encoding="utf-8")
    while True:
        signal.pause()

deadline = time.monotonic() + 2
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.001)
if marker.exists():
    ready_marker.write_text("ready", encoding="utf-8")
os._exit(0)
""".lstrip()


@contextlib.contextmanager
def _descendant_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: Literal["graceful", "resistant"],
) -> Iterator[tuple[Path, Path]]:
    marker = tmp_path / f"descendant-{mode}"
    ready_marker = tmp_path / f"descendant-{mode}-ready"
    helper = tmp_path / "spawn_descendant.py"
    helper.write_text(_DESCENDANT_HELPER, encoding="utf-8")
    real_popen = subprocess.Popen
    leader_pids: list[int] = []

    def launch_descendant(*_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        kwargs["bufsize"] = 0
        process = real_popen(
            [sys.executable, str(helper), str(marker), mode, str(ready_marker)],
            **kwargs,
        )
        leader_pids.append(process.pid)
        return process

    monkeypatch.setattr(
        "antares_cli.tools.shell_exec.subprocess.Popen",
        launch_descendant,
    )
    try:
        yield marker, ready_marker
    finally:
        for leader_pid in leader_pids:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(leader_pid, signal.SIGKILL)
        marker.unlink(missing_ok=True)
        ready_marker.unlink(missing_ok=True)


def _capture_thread_errors(monkeypatch: pytest.MonkeyPatch) -> list[BaseException]:
    errors: list[BaseException] = []

    def capture(args: threading.ExceptHookArgs) -> None:
        if args.exc_value is not None:
            errors.append(args.exc_value)

    monkeypatch.setattr(threading, "excepthook", capture)
    return errors


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_terminal_allows_read_only_and_compound_commands(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text("first = True\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("second = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {
            "command": (
                "pwd && find . -maxdepth 1 -type f | sort; grep absent missing.py || cat first.py"
            )
        },
    )

    assert result.success
    assert result.output["returncode"] == 0
    assert "first.py" in result.output["stdout"]
    assert "second.py" in result.output["stdout"]
    assert "first = True" in result.output["stdout"]


def test_terminal_allows_safe_sed_substitutions_in_pipelines(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("source = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "find . -type f | sed 's#^./##' | sort"},
    )

    assert result.success
    assert result.output["returncode"] == 0
    assert result.output["stdout"] == "source.py\n"


def test_terminal_pipeline_streams_large_input_without_buffering_every_stage(
    tmp_path: Path,
) -> None:
    (tmp_path / "large.bin").write_bytes(b"x" * 2_000_000)

    result = run_bash("cat large.bin | head -c 10", cwd=tmp_path)

    assert result["returncode"] == 0
    assert result["stdout"] == "x" * 10
    assert result["truncated"] is False


def test_terminal_cleanup_does_not_leak_reader_thread_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = _BlockingStream()
    stderr = _BlockingStream()
    process = _ExitedProcess(stdout, stderr, pid=424_242)
    real_thread = threading.Thread
    started_threads: list[threading.Thread] = []
    start_count = 0

    class FailSecondThreadStart:
        def __init__(self, *args: object, **kwargs: Any) -> None:
            self._thread = real_thread(*args, **kwargs)

        def start(self) -> None:
            nonlocal start_count
            start_count += 1
            if start_count == 2:
                raise RuntimeError("can't start new thread")
            self._thread.start()
            started_threads.append(self._thread)
            assert stderr.read_started.wait(timeout=1)

        def join(self, timeout: float | None = None) -> None:
            self._thread.join(timeout)

        def is_alive(self) -> bool:
            return self._thread.is_alive()

    thread_errors = _capture_thread_errors(monkeypatch)
    monkeypatch.setattr("antares_cli.tools.shell_exec.subprocess.Popen", lambda *_a, **_kw: process)
    monkeypatch.setattr("antares_cli.tools.shell_exec.threading.Thread", FailSecondThreadStart)
    monkeypatch.setattr("antares_cli.tools.shell_exec.os.killpg", lambda *_args: None)

    with pytest.raises(RuntimeError, match="can't start new thread"):
        run_bash("true", cwd=tmp_path)

    assert len(started_threads) == 1
    started_threads[0].join(timeout=1)
    assert not started_threads[0].is_alive()
    assert stdout.closed
    assert stderr.closed
    assert thread_errors == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group behavior")
def test_terminal_timeout_stops_descendants_after_the_group_leader_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _descendant_pipeline(tmp_path, monkeypatch, "graceful") as (marker, ready_marker):
        with pytest.raises(subprocess.TimeoutExpired):
            run_bash("true", cwd=tmp_path, timeout_seconds=2)

        assert ready_marker.read_text(encoding="utf-8") == "ready"
        deadline = time.monotonic() + 1
        while marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group behavior")
def test_terminal_timeout_force_stops_descendants_that_ignore_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _descendant_pipeline(tmp_path, monkeypatch, "resistant") as (marker, ready_marker):
        with pytest.raises(subprocess.TimeoutExpired):
            run_bash("true", cwd=tmp_path, timeout_seconds=2)

        assert ready_marker.read_text(encoding="utf-8") == "ready"
        child_pid = int(marker.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 1
        while _process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not _process_exists(child_pid)


def test_terminal_propagates_unexpected_output_capture_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stderr = _ErrorStream()
    stdout = _EmptyStream()
    process = _ExitedProcess(stdout, stderr, pid=424_243)
    thread_errors = _capture_thread_errors(monkeypatch)
    monkeypatch.setattr(
        "antares_cli.tools.shell_exec.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr("antares_cli.tools.shell_exec.os.killpg", lambda *_args: None)

    with pytest.raises(RuntimeError, match="capture read-only command output") as exc_info:
        run_bash("true", cwd=tmp_path)

    assert isinstance(exc_info.value.__cause__, OSError)
    assert str(exc_info.value.__cause__) == "synthetic pipe read failure"
    assert thread_errors == []
    assert stdout.closed
    assert stderr.closed


def test_terminal_bounds_stdout_and_stderr_during_capture(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("x" * (MAX_TOOL_OUTPUT_CHARS * 10))

    stdout_result = run_bash("cat large.txt", cwd=tmp_path)
    stderr_result = run_bash("cat " + " ".join(["missing.txt"] * 400), cwd=tmp_path)

    assert len(stdout_result["stdout"]) == MAX_TOOL_OUTPUT_CHARS
    assert stdout_result["truncated"] is True
    assert len(stderr_result["stderr"]) == MAX_TOOL_OUTPUT_CHARS
    assert stderr_result["truncated"] is True


def test_terminal_rejects_excessive_pipeline_fanout(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("terminal", {"command": " | ".join(["true"] * 17)})

    assert not result.success
    assert "pipeline stages" in (result.error_message or "")


def test_hidden_bash_alias_is_not_exposed(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("bash", {"command": "pwd"})

    assert not result.success
    assert "Unsupported tool" in (result.error_message or "")


def test_repository_command_tools_reject_model_controlled_timeout(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "tail -f app.py", "timeout_seconds": 999_999_999},
    )

    assert not result.success
    assert result.error_message == "Unsupported argument(s) for terminal: timeout_seconds"


def test_repository_tools_reject_unknown_arguments(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("read_file", {"path": "app.py", "unexpected": True})

    assert not result.success
    assert result.error_message == "Unsupported argument(s) for read_file: unexpected"


def test_read_file_rejects_an_embedded_null_path_without_raising(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("read_file", {"path": "bad\0name"})

    assert not result.success
    assert result.output is None
    assert result.error_message == "Path is outside the repository workspace: bad\\x00name"


def test_terminal_rejects_an_embedded_null_argument_without_raising(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("terminal", {"command": "cat 'bad\0/name'"})

    assert not result.success
    assert result.output is None
    assert result.error_message is not None
    assert "outside the repository" in result.error_message.lower()


def test_read_file_bounds_errors_that_include_a_model_supplied_path(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute("read_file", {"path": "x" * 20_000})

    assert not result.success
    assert result.error_message is not None
    assert len(result.error_message) <= MAX_TOOL_ERROR_CHARS
    assert result.error_message.endswith("...[tool error truncated]")


def test_terminal_rejects_excessive_glob_expansion_before_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_popen(*_args, **_kwargs):
        raise AssertionError("subprocess must not start before expansion is validated")

    monkeypatch.setattr(
        "antares_cli.tools.shell_exec.glob_module.iglob",
        lambda *_args, **_kwargs: (f"file-{index}.txt" for index in range(5_000)),
    )
    monkeypatch.setattr("antares_cli.tools.shell_exec.subprocess.Popen", unexpected_popen)

    with pytest.raises(ValueError, match="glob matched more than"):
        run_bash("cat *.txt", cwd=tmp_path)


def test_terminal_blocks_sed_substitution_write_flags(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("source = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "sed 's/True/False/w created.py' source.py"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert not (tmp_path / "created.py").exists()


def test_terminal_blocks_sed_substitution_execute_flags(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("source = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "sed 's/True/echo nested-process-ran/e' source.py"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert "nested-process-ran" not in str(result.output)


def test_terminal_allows_regex_end_anchors_and_true_fallbacks(tmp_path: Path) -> None:
    (tmp_path / "source.js").write_text("const source = true;\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {
            "command": (
                'find . -type f | grep -E "(\\.js$|\\.ts$)" && grep absent source.js || true'
            )
        },
    )

    assert result.success
    assert result.output["returncode"] == 0
    assert "source.js" in result.output["stdout"]


def test_terminal_treats_an_overlong_regex_as_an_argument_not_a_path(tmp_path: Path) -> None:
    (tmp_path / "source.txt").write_text("authentication\n", encoding="utf-8")
    router = ToolRouter(tmp_path)
    regex = "(" + "|".join(["authentication"] * 32) + ")"

    result = router.execute(
        "terminal",
        {"command": f"rg -n '{regex}' source.txt"},
    )

    assert result.success
    assert result.output["returncode"] == 0
    assert "authentication" in result.output["stdout"]


def test_terminal_blocks_find_delete_without_mutating_repository(tmp_path: Path) -> None:
    source_file = tmp_path / "keep.py"
    source_file.write_text("print('keep me')\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "pwd && find keep.py -delete"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert source_file.read_text(encoding="utf-8") == "print('keep me')\n"


def test_terminal_validates_mutation_in_skipped_conditional_branch(tmp_path: Path) -> None:
    source_file = tmp_path / "keep.py"
    source_file.write_text("print('keep me')\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "false && find keep.py -delete"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert source_file.read_text(encoding="utf-8") == "print('keep me')\n"


def test_terminal_blocks_mutating_flags_on_allowed_commands(tmp_path: Path) -> None:
    source_file = tmp_path / "keep.py"
    original_content = "unsafe = True\n"
    source_file.write_text(original_content, encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "sed -i.bak 's/True/False/' keep.py"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert source_file.read_text(encoding="utf-8") == original_content
    assert not (tmp_path / "keep.py.bak").exists()


def test_terminal_blocks_output_file_operands(tmp_path: Path) -> None:
    source_file = tmp_path / "input.txt"
    source_file.write_text("one\none\ntwo\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "uniq input.txt created.txt"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert not (tmp_path / "created.txt").exists()


def test_terminal_blocks_sensitive_paths_inside_repository(tmp_path: Path) -> None:
    sensitive_file = tmp_path / ".ssh" / "id_rsa"
    sensitive_file.parent.mkdir()
    sensitive_file.write_text("private-key-material\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "cat .ssh/id_rsa"},
    )

    assert not result.success
    assert "sensitive path" in (result.error_message or "").lower()
    assert "private-key-material" not in str(result.output)


def test_terminal_blocks_symlinks_that_escape_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside-secret\n", encoding="utf-8")
    (repository / "innocent-name").symlink_to(outside_file)
    router = ToolRouter(repository)

    result = router.execute(
        "terminal",
        {"command": "cat innocent-name"},
    )

    assert not result.success
    assert "outside the repository" in (result.error_message or "").lower()
    assert "outside-secret" not in str(result.output)


def test_terminal_resolves_paths_embedded_in_options(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("needle = True\n", encoding="utf-8")
    outside_patterns = tmp_path / "patterns.txt"
    outside_patterns.write_text("needle\n", encoding="utf-8")
    router = ToolRouter(repository)

    result = router.execute(
        "terminal",
        {"command": f"rg --file={outside_patterns} source.py"},
    )

    assert not result.success
    assert "outside the repository" in (result.error_message or "").lower()


def test_terminal_reads_from_an_immutable_repository_snapshot(tmp_path: Path) -> None:
    source_file = tmp_path / "source.py"
    source_file.write_text("snapshot_content = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)
    source_file.write_text("changed_after_start = True\n", encoding="utf-8")

    result = router.execute(
        "terminal",
        {"command": "cat source.py"},
    )

    assert result.success
    assert result.output["stdout"] == "snapshot_content = True\n"


def test_terminal_blocks_absolute_paths_back_to_original_repository(tmp_path: Path) -> None:
    source_file = tmp_path / "source.py"
    source_file.write_text("original = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": f"cat {source_file}"},
    )

    assert not result.success
    assert "relative paths" in (result.error_message or "").lower()


def test_terminal_blocks_shell_expansion_syntax(tmp_path: Path) -> None:
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "cat $HOME/outside.txt"},
    )

    assert not result.success
    assert "shell expansion" in (result.error_message or "").lower()


def test_terminal_blocks_separate_output_options(tmp_path: Path) -> None:
    (tmp_path / "input.txt").write_text("two\none\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "sort --output created.txt input.txt"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert not (tmp_path / "created.txt").exists()


def test_terminal_blocks_search_options_that_launch_subprocesses(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("needle = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "rg --search-zip needle source.py"},
    )

    assert not result.success
    assert "nested" in (result.error_message or "").lower()


def test_terminal_blocks_file_options_that_launch_subprocesses(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("needle = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "file -z source.py"},
    )

    assert not result.success
    assert "nested" in (result.error_message or "").lower()


def test_snapshot_removes_recursive_symlinks_outside_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "secret.txt").write_text("outside-secret\n", encoding="utf-8")
    (repository / "linked-directory").symlink_to(outside_directory, target_is_directory=True)
    router = ToolRouter(repository)

    snapshot_link = router.execution_root / "linked-directory"

    assert not snapshot_link.exists()
    assert not snapshot_link.is_symlink()


def test_repository_analysis_keeps_source_directories_while_pruning_caches(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text("secure = True\n", encoding="utf-8")
    for directory_name in (".git", ".venv", "node_modules"):
        directory = repository / directory_name
        directory.mkdir()
        (directory / "large.bin").write_bytes(b"x" * 1024)
    source_paths = {
        f"{directory_name}/vulnerable.py"
        for directory_name in ("build", "dist", "target", "vendor")
    }
    for relative_path in source_paths:
        path = repository / relative_path
        path.parent.mkdir()
        path.write_text("vulnerable = True\n", encoding="utf-8")

    traversed_paths = {
        path.relative_to(repository).as_posix() for path in iter_repository_files(repository)
    }

    assert source_paths <= traversed_paths

    with ReadOnlyRepositorySnapshot(repository) as snapshot:
        assert (snapshot.root / "src" / "app.py").exists()
        for relative_path in source_paths:
            assert (snapshot.root / relative_path).exists()
        for directory_name in (".git", ".venv", "node_modules"):
            assert not (snapshot.root / directory_name).exists()


def test_snapshot_excludes_sensitive_files_by_default(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
    (repository / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
    (repository / ".env.example").write_text("API_KEY=example\n", encoding="utf-8")
    (repository / "client.pem").write_text("private-key-material\n", encoding="utf-8")

    with ReadOnlyRepositorySnapshot(repository) as snapshot:
        assert (snapshot.root / "app.py").exists()
        assert not (snapshot.root / ".env").exists()
        assert not (snapshot.root / ".env.example").exists()
        assert not (snapshot.root / "client.pem").exists()


def test_snapshot_includes_only_the_exact_sensitive_file_allowed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
    (repository / ".env.example").write_text("API_KEY=example\n", encoding="utf-8")

    with ReadOnlyRepositorySnapshot(
        repository,
        allow_sensitive_files=[".env.example"],
    ) as snapshot:
        assert not (snapshot.root / ".env").exists()
        assert (snapshot.root / ".env.example").read_text(encoding="utf-8") == ("API_KEY=example\n")


@pytest.mark.parametrize(
    "requested_path",
    [".env*", "../repository/.env", ".ssh", "linked-env", "app.py"],
)
def test_snapshot_rejects_non_exact_sensitive_file_opt_ins(
    tmp_path: Path,
    requested_path: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
    (repository / ".ssh").mkdir()
    (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
    (repository / "linked-env").symlink_to(repository / ".env")

    with pytest.raises(ValueError, match="Sensitive-file opt-in"):
        ReadOnlyRepositorySnapshot(
            repository,
            allow_sensitive_files=[requested_path],
        )


def test_snapshot_applies_user_configured_ignore_patterns(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    generated = repository / "generated"
    source = repository / "src"
    generated.mkdir(parents=True)
    source.mkdir()
    (generated / "client.py").write_text("generated = True\n", encoding="utf-8")
    (source / "bundle.min.js").write_text("minified()\n", encoding="utf-8")
    (source / "app.py").write_text("source = True\n", encoding="utf-8")

    with ReadOnlyRepositorySnapshot(
        repository,
        ignore_paths=["generated", "*.min.js"],
    ) as snapshot:
        assert not (snapshot.root / "generated").exists()
        assert not (snapshot.root / "src" / "bundle.min.js").exists()
        assert (snapshot.root / "src" / "app.py").exists()


def test_snapshot_prunes_directory_glob_patterns(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "generated" / "nested").mkdir(parents=True)
    (repository / "generated" / "nested" / "client.py").write_text("generated = True\n")
    (repository / "app.py").write_text("source = True\n")

    with ReadOnlyRepositorySnapshot(repository, ignore_paths=["generated/**"]) as snapshot:
        assert not (snapshot.root / "generated").exists()
        assert (snapshot.root / "app.py").exists()


def test_snapshot_rejects_repository_over_file_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "one.py").write_text("one = True\n")
    (repository / "two.py").write_text("two = True\n")
    monkeypatch.setattr("antares_cli.tools.readonly_workspace.MAX_REPOSITORY_FILES", 1)

    with pytest.raises(ValueError, match="snapshot budget"):
        ReadOnlyRepositorySnapshot(repository)


def test_safety_gate_blocks_sensitive_paths_instead_of_warning() -> None:
    safety = validate_tool_call_safety(
        "terminal",
        {"command": "cat .aws/credentials"},
    )

    assert not safety.safe
    assert "sensitive path" in (safety.blocked_reason or "").lower()


def test_safety_gate_allows_only_an_exact_authorized_sensitive_path() -> None:
    allowed = validate_tool_call_safety(
        "terminal",
        {"command": "cat .aws/credentials"},
        allowed_sensitive_files=(".aws/credentials",),
    )
    mixed = validate_tool_call_safety(
        "terminal",
        {"command": "cat .aws/credentials .aws/config"},
        allowed_sensitive_files=(".aws/credentials",),
    )

    assert allowed.safe
    assert not mixed.safe


def test_read_file_requires_exact_sensitive_file_authorization(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("API_KEY=example\n", encoding="utf-8")
    blocked_router = ToolRouter(tmp_path)
    allowed_router = ToolRouter(tmp_path, allow_sensitive_files=[".env.example"])

    blocked = blocked_router.execute("read_file", {"path": ".env.example"})
    allowed = allowed_router.execute("read_file", {"path": ".env.example"})

    assert not blocked.success
    assert "sensitive path" in (blocked.error_message or "").lower()
    assert allowed.success
    assert "API_KEY=example" in allowed.output["stdout"]


def test_terminal_blocks_mutating_options_hidden_in_short_option_clusters(
    tmp_path: Path,
) -> None:
    (tmp_path / "input.txt").write_text("two\none\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "sort -uo created.txt input.txt"},
    )

    assert not result.success
    assert "read-only" in (result.error_message or "").lower()
    assert not (tmp_path / "created.txt").exists()


def test_read_file_streams_and_bounds_large_text_output(tmp_path: Path) -> None:
    source = tmp_path / "large.py"
    source.write_text("".join(f"line_{index:05} = True\n" for index in range(10_000)))
    router = ToolRouter(tmp_path)

    result = router.execute("read_file", {"path": "large.py"})

    assert result.success
    assert result.output["total_lines"] is None
    assert result.output["has_more"] is True
    assert len(result.output["stdout"]) == MAX_READ_FILE_CHARS
    assert result.output["truncated"] is True


def test_read_file_rejects_oversized_files_before_reading(tmp_path: Path) -> None:
    source = tmp_path / "huge.bin"
    with source.open("wb") as handle:
        handle.seek(MAX_READ_FILE_BYTES)
        handle.write(b"x")
    router = ToolRouter(tmp_path)

    result = router.execute("read_file", {"path": "huge.bin", "start_line": 1, "end_line": 1})

    assert not result.success
    assert "too large" in (result.error_message or "")


def test_read_file_validates_line_ranges(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("one\ntwo\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "read_file",
        {"path": "source.py", "start_line": 2, "end_line": 1},
    )

    assert not result.success
    assert "end_line" in (result.error_message or "")


def test_terminal_blocks_nested_execution_hidden_in_short_option_clusters(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text("needle = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "file -bz source.py"},
    )

    assert not result.success
    assert "nested" in (result.error_message or "").lower()


def test_terminal_blocks_clustered_search_helper_options(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("needle = True\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "rg -zU needle source.py"},
    )

    assert not result.success
    assert "nested" in (result.error_message or "").lower()


def test_terminal_resolves_paths_attached_to_short_options(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("needle = True\n", encoding="utf-8")
    outside_patterns = tmp_path / "patterns.txt"
    outside_patterns.write_text("needle\n", encoding="utf-8")
    router = ToolRouter(repository)

    result = router.execute(
        "terminal",
        {"command": "rg -f../patterns.txt source.py"},
    )

    assert not result.success
    assert "outside the repository" in (result.error_message or "").lower()


def test_terminal_blocks_repository_controlled_path_lists(tmp_path: Path) -> None:
    (tmp_path / "paths.txt").write_text("/etc/hosts\n", encoding="utf-8")
    router = ToolRouter(tmp_path)

    result = router.execute(
        "terminal",
        {"command": "file -f paths.txt"},
    )

    assert not result.success
    assert "path list" in (result.error_message or "").lower()
