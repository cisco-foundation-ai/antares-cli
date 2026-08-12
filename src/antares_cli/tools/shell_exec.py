# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only command execution for code exploration."""

from __future__ import annotations

import contextlib
import errno
import glob as glob_module
import math
import os
import posixpath
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from antares_cli.core.sensitive_paths import is_sensitive_repository_path

SAFE_COMMAND_ALLOWLIST = {
    "basename",
    "cat",
    "cut",
    "diff",
    "dirname",
    "du",
    "echo",
    "false",
    "file",
    "find",
    "grep",
    "head",
    "ls",
    "nl",
    "pwd",
    "realpath",
    "rg",
    "sed",
    "sort",
    "stat",
    "tail",
    "tree",
    "true",
    "uniq",
    "wc",
}

MAX_TOOL_OUTPUT_CHARS = 12_000
_MAX_CAPTURE_BYTES = MAX_TOOL_OUTPUT_CHARS * 4
_READ_CHUNK_BYTES = 16 * 1024
_TERMINATION_GRACE_SECONDS = 0.25
_MAX_COMMAND_CHARS = 16_384
_MAX_COMPOUND_COMMANDS = 32
_MAX_PIPELINE_STAGES = 16
_MAX_COMMAND_TOKENS = 512
_MAX_GLOB_MATCHES = 4_096
_MAX_STAGE_ARGV_BYTES = 128 * 1024
_SAFE_EXECUTABLE_PATH = os.pathsep.join(
    ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin")
)
_COMPOUND_OPERATORS = {"&&", "||", ";"}
_DENIED_SHELL_TOKENS = {"&", "<", ">", ">>", "<<"}
_FIND_MUTATING_PREFIXES = ("-delete", "-exec", "-ok", "-fprint", "-fprintf", "-fls")
_SENSITIVE_SYSTEM_PATHS = ("/etc/passwd", "/etc/shadow")
_SED_ALLOWED_OPTIONS = {
    "-n",
    "--quiet",
    "--silent",
    "-E",
    "-r",
    "--regexp-extended",
}
_SED_READ_EXPRESSION = re.compile(r"(?:\d+|\$)(?:,(?:\d+|\$))?p")
_GLOB_METACHARACTERS = frozenset("*?[")


@dataclass(frozen=True, slots=True)
class _ShellToken:
    value: str
    expand_glob: bool = False


def _parse_read_only_command_list(
    command: str,
) -> list[tuple[str | None, list[list[_ShellToken]]]]:
    if "\n" in command or "\r" in command:
        raise ValueError("Read-only command policy does not allow multiline commands")
    if _contains_unquoted_shell_expansion(command):
        raise ValueError("Read-only command policy does not allow shell expansion")

    tokens = _tokenize_read_only_command(command)

    commands: list[tuple[str | None, list[list[_ShellToken]]]] = []
    connector: str | None = None
    stages: list[list[_ShellToken]] = [[]]
    for token in tokens:
        if token.value == "|":
            if not stages[-1]:
                raise ValueError("Read-only command policy does not allow empty pipelines")
            stages.append([])
            continue
        if token.value in _COMPOUND_OPERATORS:
            if not stages[-1]:
                raise ValueError("Read-only command policy does not allow empty commands")
            commands.append((connector, stages))
            connector = token.value
            stages = [[]]
            continue
        if token.value in _DENIED_SHELL_TOKENS:
            raise ValueError(
                f"Read-only command policy does not allow shell operator: {token.value}"
            )
        stages[-1].append(token)
    if not stages[-1]:
        raise ValueError("Read-only command policy does not allow empty commands")
    commands.append((connector, stages))
    return commands


def _parse_read_only_command_stages(command: str) -> list[list[str]]:
    return [
        [token.value for token in stage]
        for _connector, pipeline in _parse_read_only_command_list(command)
        for stage in pipeline
    ]


def _tokenize_read_only_command(command: str) -> list[_ShellToken]:
    tokens: list[_ShellToken] = []
    characters: list[str] = []
    quote: str | None = None
    token_started = False
    expand_glob = False
    index = 0

    def flush_token() -> None:
        nonlocal token_started, expand_glob
        if not token_started:
            return
        tokens.append(_ShellToken("".join(characters), expand_glob))
        characters.clear()
        token_started = False
        expand_glob = False

    while index < len(command):
        character = command[index]
        if quote == "'":
            if character == "'":
                quote = None
            else:
                characters.append(character)
            token_started = True
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
                token_started = True
                index += 1
                continue
            if character == "\\" and index + 1 < len(command):
                escaped = command[index + 1]
                if escaped in {'"', "\\", "$", "`"}:
                    characters.append(escaped)
                    token_started = True
                    index += 2
                    continue
            characters.append(character)
            token_started = True
            index += 1
            continue
        if character.isspace():
            flush_token()
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            token_started = True
            index += 1
            continue
        if character == "\\":
            if index + 1 >= len(command):
                raise ValueError("Invalid command syntax: No escaped character")
            characters.append(command[index + 1])
            token_started = True
            index += 2
            continue
        if character in "|&;<>":
            flush_token()
            end = index + 1
            while end < len(command) and command[end] in "|&;<>":
                end += 1
            tokens.append(_ShellToken(command[index:end]))
            index = end
            continue
        characters.append(character)
        token_started = True
        if character in _GLOB_METACHARACTERS:
            expand_glob = True
        index += 1

    if quote is not None:
        raise ValueError("Invalid command syntax: No closing quotation")
    flush_token()
    return tokens


def _contains_unquoted_shell_expansion(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(command):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            elif quote == '"' and (character == "`" or _starts_shell_expansion(command, index)):
                return True
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "`" or _starts_shell_expansion(command, index):
            return True
        if character == "~" and (index == 0 or command[index - 1].isspace()):
            return True
    return False


def _starts_shell_expansion(command: str, index: int) -> bool:
    if command[index] != "$" or index + 1 >= len(command):
        return False
    return command[index + 1] in "({?#-$!@*_" or command[index + 1].isalnum()


def _validate_read_only_stage(arguments: list[_ShellToken]) -> list[_ShellToken]:
    executable = arguments[0].value
    if executable != Path(executable).name or executable not in SAFE_COMMAND_ALLOWLIST:
        if executable == "cd":
            raise ValueError(
                "cd is not supported. Commands run from the repository root. "
                "Use relative paths directly (e.g., `ls src/utils/` instead of `cd src/utils && ls`)."
            )
        raise ValueError(f"Command is not allowlisted: {executable}")

    _validate_command_arguments(executable, [argument.value for argument in arguments[1:]])
    resolved_executable = shutil.which(executable, path=_SAFE_EXECUTABLE_PATH)
    if resolved_executable is None:
        raise ValueError(f"Allowlisted command is not installed: {executable}")
    return [_ShellToken(resolved_executable), *arguments[1:]]


def _validate_command_arguments(executable: str, arguments: list[str]) -> None:
    if executable == "find" and any(
        argument.startswith(_FIND_MUTATING_PREFIXES) for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks mutating or nested find actions")

    if executable == "sed":
        _validate_sed_arguments(arguments)

    if executable == "sort" and any(
        argument in {"-o", "--output"}
        or argument.startswith(("-o", "--output="))
        or _short_option_cluster_contains(
            argument,
            "o",
            options_with_value={"k", "S", "T", "t", "o"},
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks sort output files")

    if executable == "tree" and any(
        argument == "-o"
        or argument.startswith("--output=")
        or _short_option_cluster_contains(
            argument,
            "o",
            options_with_value={"H", "L", "P", "I", "T", "o", "X"},
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks tree output files")

    if executable == "tree" and any(
        argument in {"--fromfile", "--fromtabfile"} for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks repository-controlled path lists")

    if executable == "file" and any(
        argument == "--compile"
        or _short_option_cluster_contains(
            argument,
            "C",
            options_with_value={"e", "F", "f", "m", "M", "P"},
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks compiled file databases")

    if executable == "file" and any(
        argument in {"--uncompress", "--uncompress-noreport", "--no-sandbox"}
        or any(
            _short_option_cluster_contains(
                argument,
                option,
                options_with_value={"e", "F", "f", "m", "M", "P"},
            )
            for option in ("z", "Z", "S")
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks nested or unsandboxed file inspection")

    if executable == "file" and any(
        argument in {"-f", "--files-from"}
        or argument.startswith("--files-from=")
        or _short_option_cluster_contains(
            argument,
            "f",
            options_with_value={"e", "F", "f", "m", "M", "P"},
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks repository-controlled path lists")

    if executable in {"find", "du", "sort", "wc"} and any(
        argument in {"-files0-from", "--files0-from"}
        or argument.startswith(("-files0-from=", "--files0-from="))
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks repository-controlled path lists")

    if executable == "sort" and any(
        argument == "--compress-program" or argument.startswith("--compress-program=")
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks nested sort helpers")

    if executable == "rg" and any(
        argument == "--pre"
        or argument.startswith("--pre=")
        or argument == "--hostname-bin"
        or argument.startswith("--hostname-bin=")
        or argument == "--search-zip"
        or _short_option_cluster_contains(
            argument,
            "z",
            options_with_value={
                "A",
                "B",
                "C",
                "E",
                "F",
                "e",
                "f",
                "g",
                "j",
                "m",
                "M",
                "r",
                "t",
                "T",
            },
        )
        for argument in arguments
    ):
        raise ValueError("Read-only command policy blocks nested search executables")

    if (
        executable == "uniq"
        and len(_positional_arguments(arguments, options_with_value={"-f", "-s", "-w"})) > 1
    ):
        raise ValueError("Read-only command policy blocks uniq output files")


def _positional_arguments(
    arguments: list[str],
    *,
    options_with_value: set[str],
) -> list[str]:
    positional: list[str] = []
    index = 0
    options_ended = False
    while index < len(arguments):
        argument = arguments[index]
        if not options_ended and argument == "--":
            options_ended = True
        elif not options_ended and argument in options_with_value:
            index += 1
        elif not options_ended and argument.startswith(("-", "+")):
            pass
        else:
            positional.append(argument)
        index += 1
    return positional


def _validate_read_only_stage_paths(
    stage: list[str],
    workspace_root: str | Path,
    allowed_sensitive_files: tuple[str, ...] = (),
) -> str | None:
    if not stage:
        return None
    root = Path(workspace_root).resolve()

    for token in stage[1:]:
        for path_candidate in _path_candidates(token):
            if _glob_matches_sensitive_path(root, path_candidate):
                return f"Sensitive path is blocked: {path_candidate}"
            if Path(path_candidate).is_absolute():
                if _references_sensitive_path(path_candidate, allowed_sensitive_files):
                    return f"Sensitive path is blocked: {path_candidate}"
                if not _path_stays_inside_workspace(root, path_candidate):
                    return f"Path is outside the repository workspace: {path_candidate}"
                return "Absolute repository paths are blocked. Use relative paths instead."
            if not _looks_like_path_token(path_candidate) and not _workspace_path_exists(
                root, path_candidate
            ):
                continue
            if _references_sensitive_path(path_candidate, allowed_sensitive_files):
                return f"Sensitive path is blocked: {path_candidate}"
            if not _path_stays_inside_workspace(root, path_candidate):
                return (
                    f"Path is outside the repository workspace: {path_candidate}. "
                    "Use relative paths from the repository root "
                    "(e.g., src/utils.py instead of /workspace/repo/src/utils.py)."
                )
    return None


def _glob_matches_sensitive_path(workspace_root: Path, raw_path: str) -> bool:
    if not any(character in raw_path for character in _GLOB_METACHARACTERS):
        return False
    for match_count, match in enumerate(
        glob_module.iglob(raw_path, root_dir=workspace_root),
        start=1,
    ):
        if match_count > _MAX_GLOB_MATCHES:
            raise ValueError(
                f"Read-only command glob matched more than {_MAX_GLOB_MATCHES:,} paths"
            )
        if is_sensitive_repository_path(match):
            return True
    return False


def _path_stays_inside_workspace(workspace_root: Path, raw_path: str) -> bool:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = workspace_root / candidate
    try:
        resolved = candidate.resolve()
    except ValueError:
        return False
    except OSError:
        resolved = candidate.absolute()
    return resolved == workspace_root or workspace_root in resolved.parents


def _workspace_path_exists(workspace_root: Path, raw_value: str) -> bool:
    if raw_value.startswith("-"):
        return False
    candidate = workspace_root / raw_value
    try:
        return candidate.is_symlink() or candidate.exists()
    except ValueError:
        return True
    except OSError as error:
        # Search expressions are not path operands. On filesystems with a
        # component-length limit, probing a long regex can raise before the
        # command is allowed to interpret it. Other filesystem errors remain
        # path candidates so the containment check handles them fail-closed.
        return error.errno != errno.ENAMETOOLONG


def _looks_like_path_token(token: str) -> bool:
    if token in {"..", "."}:
        return token == ".."
    if token.startswith("/"):
        return True
    normalized = token.replace("\\", "/")
    return "/" in normalized or ".." in normalized.split("/")


def _references_sensitive_path(
    value: str,
    allowed_sensitive_files: tuple[str, ...] = (),
) -> bool:
    normalized = value.replace("\\", "/").lower()
    if any(system_path in normalized for system_path in _SENSITIVE_SYSTEM_PATHS):
        return True
    canonical = posixpath.normpath(normalized)
    while canonical.startswith("./"):
        canonical = canonical[2:]
    normalized_allowed = {path.casefold() for path in allowed_sensitive_files}
    return is_sensitive_repository_path(canonical) and canonical not in normalized_allowed


def _path_candidates(token: str) -> tuple[str, ...]:
    if token.startswith("-") and "=" in token:
        return token, token.split("=", maxsplit=1)[1]
    if token.startswith("-"):
        marker_offsets = [
            offset for marker in ("../", "./", "/", "~") if (offset := token.find(marker, 2)) >= 2
        ]
        if marker_offsets:
            return token, token[min(marker_offsets) :]
    return (token,)


def _short_option_cluster_contains(
    argument: str,
    option: str,
    *,
    options_with_value: set[str],
) -> bool:
    if not argument.startswith("-") or argument.startswith("--"):
        return False
    for candidate in argument[1:]:
        if candidate == option:
            return True
        if candidate in options_with_value:
            return False
    return False


def _validate_sed_arguments(arguments: list[str]) -> None:
    expressions: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-i", "--in-place"} or argument.startswith(("-i", "--in-place=")):
            raise ValueError("Read-only command policy blocks sed in-place editing")
        if argument == "-e":
            index += 1
            if index >= len(arguments):
                raise ValueError("sed -e requires an expression")
            expressions.append(arguments[index])
        elif argument.startswith("-"):
            if argument not in _SED_ALLOWED_OPTIONS:
                raise ValueError(f"Read-only command policy blocks sed option: {argument}")
        elif not expressions:
            expressions.append(argument)
        index += 1

    if not expressions or any(not _is_safe_sed_expression(item) for item in expressions):
        raise ValueError(
            "Read-only command policy permits sed only for line-range printing or "
            "non-writing substitutions"
        )


def _is_safe_sed_expression(expression: str) -> bool:
    if _SED_READ_EXPRESSION.fullmatch(expression) is not None:
        return True
    if len(expression) < 4 or expression[0] != "s":
        return False
    delimiter = expression[1]
    if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
        return False

    index = 2
    for _section in range(2):
        while index < len(expression):
            character = expression[index]
            if character == "\\" and index + 1 < len(expression):
                index += 2
                continue
            index += 1
            if character == delimiter:
                break
        else:
            return False

    flags = expression[index:]
    return all(character in "0123456789gIpMm" for character in flags)


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": _SAFE_EXECUTABLE_PATH,
        "HOME": "/nonexistent",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "NO_COLOR": "1",
    }
    return environment


_OPTIONS_CONSUMING_GLOB_PATTERN = {
    "find": frozenset(
        {
            "-name",
            "-iname",
            "-path",
            "-ipath",
            "-wholename",
            "-iwholename",
            "-lname",
            "-ilname",
            "-regex",
            "-iregex",
        }
    ),
    "grep": frozenset({"--include", "--exclude", "--exclude-dir"}),
    "rg": frozenset({"--glob", "--iglob", "-g", "--type-add"}),
    "tree": frozenset({"-P", "-I"}),
}


def _expand_globs(stage: list[_ShellToken], working_directory: str | None) -> list[str]:
    """Expand shell-style globs in positional arguments, mimicking bash.

    The executable (stage[0]) is never expanded. Arguments following options
    that expect glob/regex patterns (like find -name or rg --glob) are also
    never expanded. For remaining positional arguments that contain glob
    metacharacters, we expand relative to the working directory. If a glob
    matches nothing, the literal token is preserved (matching bash default
    behavior without nullglob).
    """
    if working_directory is None:
        return [token.value for token in stage]
    expanded: list[str] = [stage[0].value]
    pattern_options = _OPTIONS_CONSUMING_GLOB_PATTERN.get(Path(stage[0].value).name, frozenset())
    skip_next = False
    for token in stage[1:]:
        argument = token.value
        if skip_next:
            expanded.append(argument)
            skip_next = False
            continue
        if argument in pattern_options:
            expanded.append(argument)
            skip_next = True
            continue
        if argument.startswith("-"):
            expanded.append(argument)
            continue
        if not token.expand_glob:
            expanded.append(argument)
            continue
        matches: list[str] = []
        for match in glob_module.iglob(argument, root_dir=working_directory):
            matches.append(match)
            if len(matches) > _MAX_GLOB_MATCHES:
                raise ValueError(
                    f"Read-only command glob matched more than {_MAX_GLOB_MATCHES:,} paths"
                )
        matches.sort()
        if matches:
            expanded.extend(matches)
        else:
            expanded.append(argument)
    return expanded


def _validate_command_size(
    command: str,
    command_list: list[tuple[str | None, list[list[_ShellToken]]]],
) -> None:
    if len(command) > _MAX_COMMAND_CHARS:
        raise ValueError(f"Read-only command exceeds the {_MAX_COMMAND_CHARS:,}-character limit")
    if len(command_list) > _MAX_COMPOUND_COMMANDS:
        raise ValueError(
            f"Read-only command contains more than {_MAX_COMPOUND_COMMANDS} compound entries"
        )
    token_count = 0
    for _connector, pipeline in command_list:
        if len(pipeline) > _MAX_PIPELINE_STAGES:
            raise ValueError(
                f"Read-only command contains more than {_MAX_PIPELINE_STAGES} pipeline stages"
            )
        token_count += sum(len(stage) for stage in pipeline)
    if token_count > _MAX_COMMAND_TOKENS:
        raise ValueError(f"Read-only command contains more than {_MAX_COMMAND_TOKENS} arguments")


def _prepare_pipeline(
    stages: list[list[_ShellToken]],
    *,
    working_directory: str | None,
    allowed_sensitive_files: tuple[str, ...],
) -> list[list[str]]:
    """Expand and validate every stage before starting any subprocess."""
    expanded_stages: list[list[str]] = []
    for stage in stages:
        expanded_stage = _expand_globs(stage, working_directory)
        argv_bytes = sum(len(argument.encode("utf-8")) + 1 for argument in expanded_stage)
        if argv_bytes > _MAX_STAGE_ARGV_BYTES:
            raise ValueError(
                f"Read-only command arguments exceed the {_MAX_STAGE_ARGV_BYTES:,}-byte limit"
            )
        _validate_command_arguments(Path(expanded_stage[0]).name, expanded_stage[1:])
        if working_directory is not None:
            path_error = _validate_read_only_stage_paths(
                expanded_stage,
                working_directory,
                allowed_sensitive_files,
            )
            if path_error is not None:
                raise ValueError(path_error)
        expanded_stages.append(expanded_stage)
    return expanded_stages


@dataclass(slots=True)
class _BoundedCapture:
    buffer: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    _lock: Any = field(default_factory=threading.Lock)

    def append(self, chunk: bytes) -> None:
        with self._lock:
            remaining = _MAX_CAPTURE_BYTES - len(self.buffer)
            if remaining > 0:
                self.buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.truncated = True


def _drain_stream(
    stream: IO[bytes],
    capture: _BoundedCapture,
    shutdown: threading.Event,
    reader_errors: queue.SimpleQueue[Exception],
) -> None:
    try:
        while chunk := stream.read(_READ_CHUNK_BYTES):
            capture.append(chunk)
    except (OSError, ValueError) as error:
        if not shutdown.is_set():
            reader_errors.put(error)
    except Exception as error:
        reader_errors.put(error)


def _raise_reader_error(reader_errors: queue.SimpleQueue[Exception]) -> None:
    try:
        error = reader_errors.get_nowait()
    except queue.Empty:
        return
    raise RuntimeError("Failed to capture read-only command output") from error


def _signal_process(process: subprocess.Popen[bytes], *, force: bool) -> None:
    if os.name == "nt":
        if process.poll() is not None:
            return
        if force:
            process.kill()
        else:
            process.terminate()
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)


def _terminate_pipeline(processes: list[subprocess.Popen[bytes]]) -> None:
    """Terminate every process group in a pipeline, escalating after a short grace period."""
    if not processes:
        return
    for process in processes:
        _signal_process(process, force=False)

    grace_deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    for process in processes:
        if process.poll() is not None:
            continue
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=max(0.0, grace_deadline - time.monotonic()))

    remaining_grace = grace_deadline - time.monotonic()
    if remaining_grace > 0:
        time.sleep(remaining_grace)
    for process in processes:
        _signal_process(process, force=True)

    for process in processes:
        if process.poll() is None:
            process.wait()


def _close_pipeline_streams(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                with contextlib.suppress(OSError, ValueError):
                    stream.close()


def _run_pipeline(
    stages: list[list[_ShellToken]],
    *,
    working_directory: str | None,
    deadline: float,
    timeout_seconds: float,
    allowed_sensitive_files: tuple[str, ...],
) -> tuple[str, str, int, bool]:
    """Run one pipeline with OS pipes and cross-platform bounded output readers."""
    expanded_stages = _prepare_pipeline(
        stages,
        working_directory=working_directory,
        allowed_sensitive_files=allowed_sensitive_files,
    )
    processes: list[subprocess.Popen[bytes]] = []
    previous_stdout: IO[bytes] | None = None
    reader_threads: list[threading.Thread] = []
    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    shutdown = threading.Event()
    reader_errors: queue.SimpleQueue[Exception] = queue.SimpleQueue()

    try:
        for expanded_stage in expanded_stages:
            if deadline - time.monotonic() <= 0:
                raise subprocess.TimeoutExpired(expanded_stage, timeout_seconds)

            process_group_options: dict[str, Any] = (
                {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
                if os.name == "nt"
                else {"start_new_session": True}
            )
            process = subprocess.Popen(
                expanded_stage,
                cwd=working_directory,
                stdin=previous_stdout if previous_stdout is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=_safe_environment(),
                **process_group_options,
            )
            processes.append(process)
            if previous_stdout is not None:
                previous_stdout.close()
            previous_stdout = process.stdout
            if process.stderr is None:
                raise RuntimeError("Pipeline process did not expose a stderr stream")
            stderr_reader = threading.Thread(
                target=_drain_stream,
                args=(process.stderr, stderr_capture, shutdown, reader_errors),
                daemon=True,
            )
            stderr_reader.start()
            reader_threads.append(stderr_reader)

        final_stdout = processes[-1].stdout
        if final_stdout is None:
            raise RuntimeError("Pipeline process did not expose a stdout stream")
        stdout_reader = threading.Thread(
            target=_drain_stream,
            args=(final_stdout, stdout_capture, shutdown, reader_errors),
            daemon=True,
        )
        stdout_reader.start()
        reader_threads.append(stdout_reader)

        while any(process.poll() is None for process in processes):
            _raise_reader_error(reader_errors)
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(expanded_stages[-1], timeout_seconds)
            if stdout_capture.truncated or stderr_capture.truncated:
                _terminate_pipeline(processes)
                break
            time.sleep(min(remaining_seconds, 0.01))

        for process in processes:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(expanded_stages[-1], timeout_seconds)
            process.wait(timeout=remaining_seconds)
        for reader in reader_threads:
            remaining_seconds = deadline - time.monotonic()
            reader.join(timeout=max(0.0, remaining_seconds))
            if reader.is_alive():
                raise subprocess.TimeoutExpired(expanded_stages[-1], timeout_seconds)
        _raise_reader_error(reader_errors)
    except BaseException:
        shutdown.set()
        _terminate_pipeline(processes)
        _close_pipeline_streams(processes)
        cleanup_deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
        for reader in reader_threads:
            reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
        raise
    finally:
        _close_pipeline_streams(processes)

    stdout = stdout_capture.buffer.decode("utf-8", errors="replace")
    stderr = stderr_capture.buffer.decode("utf-8", errors="replace")
    truncated = stdout_capture.truncated or stderr_capture.truncated
    if len(stdout) > MAX_TOOL_OUTPUT_CHARS:
        stdout = stdout[:MAX_TOOL_OUTPUT_CHARS]
        truncated = True
    if len(stderr) > MAX_TOOL_OUTPUT_CHARS:
        stderr = stderr[:MAX_TOOL_OUTPUT_CHARS]
        truncated = True
    return stdout, stderr, processes[-1].returncode, truncated


def _append_text_bounded(current: str, addition: str) -> tuple[str, bool]:
    remaining = MAX_TOOL_OUTPUT_CHARS - len(current)
    if remaining <= 0:
        return current, bool(addition)
    return current + addition[:remaining], len(addition) > remaining


def run_bash(
    command: str,
    *,
    cwd: str | Path | None = None,
    timeout_seconds: float = 30,
    allowed_sensitive_files: tuple[str, ...] = (),
) -> dict[str, object]:
    if not command or not command.strip():
        raise ValueError("Command cannot be empty")
    stripped_command = command.strip()
    if len(stripped_command) > _MAX_COMMAND_CHARS:
        raise ValueError(f"Read-only command exceeds the {_MAX_COMMAND_CHARS:,}-character limit")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a finite number greater than zero")
    command_list = [
        (connector, [_validate_read_only_stage(stage) for stage in pipeline])
        for connector, pipeline in _parse_read_only_command_list(stripped_command)
    ]
    _validate_command_size(command, command_list)
    working_directory = str(cwd) if cwd is not None else None
    deadline = time.monotonic() + timeout_seconds
    stdout = ""
    stderr = ""
    truncated = False
    return_code = 0
    for connector, pipeline in command_list:
        if connector == "&&" and return_code != 0:
            continue
        if connector == "||" and return_code == 0:
            continue
        pipeline_stdout, pipeline_stderr, return_code, pipeline_truncated = _run_pipeline(
            pipeline,
            working_directory=working_directory,
            deadline=deadline,
            timeout_seconds=timeout_seconds,
            allowed_sensitive_files=allowed_sensitive_files,
        )
        stdout, stdout_truncated = _append_text_bounded(stdout, pipeline_stdout)
        stderr, stderr_truncated = _append_text_bounded(stderr, pipeline_stderr)
        truncated = truncated or pipeline_truncated or stdout_truncated or stderr_truncated
    return {
        "command": command,
        "returncode": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated,
    }
