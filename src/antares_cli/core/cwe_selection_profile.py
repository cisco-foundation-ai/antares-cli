# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository profiling for CWE-backed check selection."""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from antares_cli.core.cwe_selection_evidence import detect_cwe_evidence
from antares_cli.core.cwe_selection_models import RepositoryProfile
from antares_cli.core.repository_paths import (
    MAX_REPOSITORY_BYTES,
    MAX_REPOSITORY_FILE_BYTES,
    MAX_REPOSITORY_FILES,
    iter_repository_files,
)
from antares_cli.core.sensitive_paths import resolve_allowed_sensitive_files

_MAX_PROFILE_FILES = 300
_MAX_PROFILE_FILE_BYTES = 1_000_000
_MAX_PRIORITY_PROFILE_FILES = 75

_SECURITY_SENSITIVE_PATH_MARKERS = (
    "accesscontrol",
    "archive",
    "auth",
    "command",
    "crypto",
    "csrf",
    "deserialize",
    "escape",
    "permission",
    "printer",
    "redirect",
    "requesthandler",
    "sanitize",
    "security",
    "tls",
    "terminal",
    "upload",
    "validate",
    "validation",
    "xsrf",
)

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".tf": "terraform",
    ".v": "verilog",
    ".vh": "verilog",
    ".vhd": "vhdl",
    ".vhdl": "vhdl",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".lua": "lua",
    ".dart": "dart",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".sol": "solidity",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".vue": "vue",
    ".s": "assembly",
    ".asm": "assembly",
}

_FRAMEWORK_DEPENDENCY_EXACT = {
    "flask": "flask",
    "fastapi": "fastapi",
    "django": "django",
    "express": "express",
    "next": "next",
    "react": "react",
    "react-native": "react-native",
    "koa": "koa",
    "@hapi/hapi": "hapi",
    "@nestjs/core": "nestjs",
    "@grpc/grpc-js": "grpc",
    "rails": "rails",
    "torch": "torch",
    "pytorch": "pytorch",
    "tensorflow": "tensorflow",
    "keras": "keras",
    "scikit-learn": "scikit-learn",
    "sklearn": "sklearn",
    "github.com/gin-gonic/gin": "gin",
    "github.com/gorilla/mux": "gorilla",
    "github.com/labstack/echo": "echo",
    "github.com/gofiber/fiber": "fiber",
    "google.golang.org/grpc": "grpc",
}
_FRAMEWORK_DEPENDENCY_PREFIXES = {
    "org.springframework": "spring",
    "spring-": "spring",
    "io.vertx": "vertx",
    "vertx-": "vertx",
    "io.netty": "netty",
    "netty-": "netty",
    "io.undertow": "undertow",
    "undertow-": "undertow",
    "io.grpc": "grpc",
    "grpc-": "grpc",
    "org.eclipse.jetty": "jetty",
    "jetty-": "jetty",
    "io.quarkus": "quarkus",
    "quarkus-": "quarkus",
    "io.micronaut": "micronaut",
    "micronaut-": "micronaut",
    "org.apache.tomcat": "tomcat",
    "tomcat-": "tomcat",
    "org.jboss.resteasy": "resteasy",
    "resteasy-": "resteasy",
    "com.vaadin": "vaadin",
    "vaadin-": "vaadin",
    "androidx.": "android",
}
_DEPENDENCY_CAPABILITY_PREFIXES = {
    "parser_signals": (
        "ajv",
        "com.fasterxml.jackson",
        "com.google.code.gson",
        "jsonschema",
        "org.tomlj",
        "org.yaml:snakeyaml",
        "serde_json",
        "serde_yaml",
        "toml",
    ),
    "logging_signals": (
        "ch.qos.logback",
        "github.com/sirupsen/logrus",
        "go.uber.org/zap",
        "org.apache.logging.log4j",
        "org.slf4j",
        "pino",
        "structlog",
        "winston",
    ),
    "configuration_signals": (
        "com.typesafe",
        "configparser",
        "dotenv",
        "github.com/spf13/viper",
        "org.apache.commons:commons-configuration",
        "python-dotenv",
    ),
}
_DEPENDENCY_MANIFEST_NAMES = {
    "cargo.toml",
    "composer.json",
    "gemfile",
    "go.mod",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "build.gradle",
    "build.gradle.kts",
}
_SECRET_SIGNAL_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:password|passwd|api[_-]?key|secret|token|credential|"
    r"(?:access|api|auth|bearer|csrf|id|refresh|session)[_-]?token)"
    r"(?:s|[^a-z0-9]|$)"
)


@dataclass(slots=True)
class ProfileSignals:
    frameworks: set[str] = field(default_factory=set)
    package_managers: set[str] = field(default_factory=set)
    dependency_files: set[str] = field(default_factory=set)
    route_files: set[str] = field(default_factory=set)
    auth_signals: set[str] = field(default_factory=set)
    data_store_signals: set[str] = field(default_factory=set)
    template_signals: set[str] = field(default_factory=set)
    file_io_signals: set[str] = field(default_factory=set)
    network_client_signals: set[str] = field(default_factory=set)
    deserialization_signals: set[str] = field(default_factory=set)
    crypto_signals: set[str] = field(default_factory=set)
    native_code_signals: set[str] = field(default_factory=set)
    iac_signals: set[str] = field(default_factory=set)
    secret_signals: set[str] = field(default_factory=set)
    request_input_signals: set[str] = field(default_factory=set)
    upload_signals: set[str] = field(default_factory=set)
    logging_signals: set[str] = field(default_factory=set)
    parser_signals: set[str] = field(default_factory=set)
    configuration_signals: set[str] = field(default_factory=set)
    cwe_evidence: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    cwe_evidence_files: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    cwe_evidence_scores: dict[str, int] = field(default_factory=dict)


class RepositoryProfiler:
    """Builds a cheap static profile without model inference."""

    def profile(
        self,
        target: Path,
        *,
        ignore_paths: list[str] | tuple[str, ...] = (),
        allow_sensitive_files: list[str] | tuple[str, ...] = (),
    ) -> RepositoryProfile:
        root = target.resolve()
        files = list(
            _iter_profile_files(
                root,
                ignore_paths=ignore_paths,
                allow_sensitive_files=resolve_allowed_sensitive_files(
                    root,
                    allow_sensitive_files,
                ),
            )
        )
        language_counts = Counter(
            language for file_path in files if (language := _language_for_path(file_path))
        )
        signal_files = [file_path for file_path in files if _is_profile_signal_file(file_path)]
        sampled_signal_files = _sample_profile_signal_files(root, signal_files)
        signals = _collect_profile_signals(root, sampled_signal_files)
        return _build_repository_profile(
            root=root,
            files=files,
            languages=_language_weights(language_counts),
            signals=signals,
        )


def _collect_profile_signals(root: Path, files: list[Path]) -> ProfileSignals:
    signals = ProfileSignals()
    for file_path in files:
        relative_path = _relative_label(file_path, root)
        _record_manifest_signals(file_path, relative_path, signals)
        if _language_for_path(file_path) in {"terraform"} or file_path.name == "Dockerfile":
            signals.iac_signals.add(relative_path)
        lower_text = _read_small_text(file_path).lower()
        language = _language_for_path(file_path)
        if lower_text and language is not None:
            _record_content_signals(lower_text, relative_path, signals)
            _record_cwe_evidence(lower_text, language, relative_path, signals)
    return signals


def _build_repository_profile(
    *,
    root: Path,
    files: list[Path],
    languages: dict[str, float],
    signals: ProfileSignals,
) -> RepositoryProfile:
    return RepositoryProfile(
        root=root,
        languages=languages,
        frameworks=tuple(sorted(signals.frameworks)),
        package_managers=tuple(sorted(signals.package_managers)),
        dependency_files=tuple(sorted(signals.dependency_files)),
        route_files=tuple(sorted(signals.route_files)),
        auth_signals=tuple(sorted(signals.auth_signals)),
        data_store_signals=tuple(sorted(signals.data_store_signals)),
        template_signals=tuple(sorted(signals.template_signals)),
        file_io_signals=tuple(sorted(signals.file_io_signals)),
        network_client_signals=tuple(sorted(signals.network_client_signals)),
        deserialization_signals=tuple(sorted(signals.deserialization_signals)),
        crypto_signals=tuple(sorted(signals.crypto_signals)),
        native_code_signals=tuple(sorted(signals.native_code_signals)),
        iac_signals=tuple(sorted(signals.iac_signals)),
        secret_signals=tuple(sorted(signals.secret_signals)),
        request_input_signals=tuple(sorted(signals.request_input_signals)),
        upload_signals=tuple(sorted(signals.upload_signals)),
        logging_signals=tuple(sorted(signals.logging_signals)),
        parser_signals=tuple(sorted(signals.parser_signals)),
        configuration_signals=tuple(sorted(signals.configuration_signals)),
        cwe_evidence={
            cwe_id: tuple(sorted(evidence))
            for cwe_id, evidence in sorted(signals.cwe_evidence.items())
        },
        cwe_evidence_files={
            cwe_id: tuple(sorted(files))
            for cwe_id, files in sorted(signals.cwe_evidence_files.items())
        },
        cwe_evidence_scores=dict(sorted(signals.cwe_evidence_scores.items())),
        confidence=_profile_confidence(languages, signals, files),
    )


def _iter_profile_files(
    root: Path,
    *,
    ignore_paths: list[str] | tuple[str, ...] = (),
    allow_sensitive_files: tuple[str, ...] = (),
) -> list[Path]:
    files: list[Path] = []
    repository_file_count = 0
    repository_bytes = 0
    for path in iter_repository_files(
        root,
        ignore_paths=ignore_paths,
        allow_sensitive_files=allow_sensitive_files,
    ):
        try:
            if not path.is_file():
                continue
            file_size = path.stat().st_size
        except FileNotFoundError:
            continue
        if file_size > MAX_REPOSITORY_FILE_BYTES:
            raise ValueError(
                f"Repository file exceeds the {MAX_REPOSITORY_FILE_BYTES:,}-byte snapshot "
                f"limit: {path.relative_to(root).as_posix()}. "
                "Add it to ignore_paths if it is not source code."
            )
        repository_file_count += 1
        repository_bytes += file_size
        if repository_file_count > MAX_REPOSITORY_FILES or repository_bytes > MAX_REPOSITORY_BYTES:
            raise ValueError(
                "Repository exceeds the read-only snapshot budget "
                f"({MAX_REPOSITORY_FILES:,} files / {MAX_REPOSITORY_BYTES:,} bytes). "
                "Exclude dependency, build, or generated trees with ignore_paths."
            )
        if file_size <= _MAX_PROFILE_FILE_BYTES:
            files.append(path)
    return sorted(files)


def _is_runtime_signal_file(path: Path) -> bool:
    return _language_for_path(path) is not None


def _is_profile_signal_file(path: Path) -> bool:
    return (
        _is_runtime_signal_file(path)
        or path.name.lower() in _DEPENDENCY_MANIFEST_NAMES
        or path.name == "Dockerfile"
    )


def _sample_profile_signal_files(root: Path, files: list[Path]) -> list[Path]:
    manifests = [
        path
        for path in files
        if path.name.lower() in _DEPENDENCY_MANIFEST_NAMES or path.name == "Dockerfile"
    ]
    sampled = manifests[:_MAX_PROFILE_FILES]
    if len(sampled) >= _MAX_PROFILE_FILES:
        return sampled

    manifest_set = set(manifests)
    remaining = [path for path in files if path not in manifest_set]
    priority_files = [path for path in remaining if _is_security_sensitive_profile_path(path, root)]
    priority_limit = min(
        _MAX_PRIORITY_PROFILE_FILES,
        _MAX_PROFILE_FILES - len(sampled),
    )
    sampled.extend(_round_robin_profile_files(root, priority_files, priority_limit))
    sampled_set = set(sampled)
    sampled.extend(
        _round_robin_profile_files(
            root,
            [path for path in remaining if path not in sampled_set],
            _MAX_PROFILE_FILES - len(sampled),
        )
    )
    return sampled


def _round_robin_profile_files(root: Path, files: list[Path], limit: int) -> list[Path]:
    if limit <= 0:
        return []
    sampled: list[Path] = []
    buckets: dict[tuple[str, str], deque[Path]] = defaultdict(deque)
    for path in files:
        relative = path.relative_to(root)
        component = relative.parts[0] if len(relative.parts) > 1 else "."
        language = _language_for_path(path) or "other"
        buckets[(component, language)].append(path)

    active_buckets = [buckets[key] for key in sorted(buckets)]
    while active_buckets and len(sampled) < limit:
        next_round: list[deque[Path]] = []
        for bucket in active_buckets:
            sampled.append(bucket.popleft())
            if bucket:
                next_round.append(bucket)
            if len(sampled) >= limit:
                break
        active_buckets = next_round
    return sampled


def _is_security_sensitive_profile_path(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix().lower()
    return any(marker in relative for marker in _SECURITY_SENSITIVE_PATH_MARKERS)


def _language_for_path(path: Path) -> str | None:
    if path.name == "Dockerfile":
        return "dockerfile"
    return _LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _language_weights(language_counts: Counter[str]) -> dict[str, float]:
    total = sum(language_counts.values())
    if total == 0:
        return {}
    return {
        language: count / total
        for language, count in sorted(language_counts.items(), key=lambda item: item[0])
    }


def _record_manifest_signals(
    file_path: Path,
    relative_path: str,
    signals: ProfileSignals,
) -> None:
    name = file_path.name.lower()
    if name in _DEPENDENCY_MANIFEST_NAMES:
        signals.dependency_files.add(relative_path)
    package_manager = _package_manager_for_manifest(name)
    if package_manager is not None:
        signals.package_managers.add(package_manager)
    if name == "dockerfile" or file_path.suffix.lower() == ".tf":
        signals.iac_signals.add(relative_path)

    if name in _DEPENDENCY_MANIFEST_NAMES:
        for dependency in _manifest_dependency_names(file_path):
            framework = _framework_for_dependency(dependency)
            if framework is not None:
                signals.frameworks.add(framework)
            _record_dependency_capability_signals(dependency, relative_path, signals)


def _record_dependency_capability_signals(
    dependency: str,
    relative_path: str,
    signals: ProfileSignals,
) -> None:
    normalized = dependency.lower()
    for profile_field, prefixes in _DEPENDENCY_CAPABILITY_PREFIXES.items():
        if any(normalized.startswith(prefix) for prefix in prefixes):
            getattr(signals, profile_field).add(relative_path)


def _package_manager_for_manifest(name: str) -> str | None:
    package_managers = {
        "pyproject.toml": "python",
        "requirements.txt": "python",
        "package.json": "npm",
        "go.mod": "go",
        "cargo.toml": "cargo",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "build.gradle.kts": "gradle",
        "gemfile": "ruby",
        "composer.json": "composer",
    }
    return package_managers.get(name)


def _manifest_dependency_names(file_path: Path) -> set[str]:
    name = file_path.name.lower()
    text = _read_manifest_text(file_path)
    try:
        if name in {"package.json", "composer.json"}:
            payload = json.loads(text)
            if not isinstance(payload, dict):
                return set()
            sections = (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
                "require",
                "require-dev",
            )
            return {
                str(dependency).lower()
                for section in sections
                if isinstance(payload.get(section), dict)
                for dependency in payload[section]
            }
        if name in {"pyproject.toml", "cargo.toml"}:
            payload = tomllib.loads(text)
            return _toml_dependency_names(payload, name)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError):
        return set()
    if name == "requirements.txt":
        return {
            match.group(1).lower()
            for line in text.splitlines()
            if (match := re.match(r"\s*([A-Za-z0-9_.-]+)", line)) is not None
        }
    if name == "go.mod":
        return {
            match.group(1).lower()
            for line in text.splitlines()
            if (match := re.match(r"\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)\s+v", line)) is not None
        }
    if name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
        return {
            dependency.lower()
            for dependency in re.findall(
                r"(?:<groupId>|<artifactId>|['\"])([A-Za-z0-9_.-]+(?:[:/][A-Za-z0-9_.-]+)*)",
                text,
            )
        }
    if name == "gemfile":
        return {dependency.lower() for dependency in re.findall(r"\bgem\s+['\"]([^'\"]+)", text)}
    return set()


def _toml_dependency_names(payload: dict[str, object], manifest_name: str) -> set[str]:
    dependencies: set[str] = set()
    if manifest_name == "cargo.toml":
        for section_name, section in payload.items():
            if "dependencies" in section_name and isinstance(section, dict):
                dependencies.update(str(name).lower() for name in section)
        return dependencies
    project = payload.get("project")
    if isinstance(project, dict):
        raw_dependencies = project.get("dependencies", [])
        if isinstance(raw_dependencies, list):
            dependencies.update(
                match.group(1).lower()
                for value in raw_dependencies
                if isinstance(value, str)
                if (match := re.match(r"\s*([A-Za-z0-9_.-]+)", value)) is not None
            )
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    dependencies.update(
                        match.group(1).lower()
                        for value in values
                        if isinstance(value, str)
                        if (match := re.match(r"\s*([A-Za-z0-9_.-]+)", value)) is not None
                    )
    tool = payload.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            dependencies.update(str(name).lower() for name in poetry["dependencies"])
    return dependencies


def _framework_for_dependency(dependency: str) -> str | None:
    normalized = dependency.removeprefix("@types/").lower()
    normalized = re.sub(r"/v[2-9][0-9]*$", "", normalized)
    exact = _FRAMEWORK_DEPENDENCY_EXACT.get(normalized)
    if exact is not None:
        return exact
    for prefix, framework in _FRAMEWORK_DEPENDENCY_PREFIXES.items():
        if normalized.startswith(prefix):
            return framework
    return None


def _record_content_signals(
    lower_text: str,
    relative_path: str,
    signals: ProfileSignals,
) -> None:
    signal_rules = (
        (
            (
                "@app.route",
                "@router.",
                "app.get(",
                "router.get(",
                ".handlefunc(",
                "http.handlefunc(",
                "servehttp(",
                "@getmapping",
                "@postmapping",
                "@requestmapping",
            ),
            signals.route_files,
        ),
        (
            (
                "request[",
                "request.args",
                "request.form",
                "request.files",
                "request.json",
                "request.get_json",
                "request.query_params",
                "request.path_params",
                "request.body",
                "request.data",
                "request.values",
                "req.body",
                "req.query",
                "req.params",
                "req.files",
                "*http.request",
                ".formvalue(",
                ".url.query(",
                ".parsemultipartform(",
                ".multipartform",
                "@requestparam",
                "httpservletrequest",
            ),
            signals.request_input_signals,
        ),
        (("login_required", "auth_required", "is_authenticated", "jwt"), signals.auth_signals),
        (
            (
                "cursor.execute",
                "sqlalchemy",
                "sequelize",
                "prisma",
                '"database/sql"',
                ".querycontext(",
                ".execcontext(",
            ),
            signals.data_store_signals,
        ),
        (("render_template", "innerhtml", "dangerouslysetinnerhtml"), signals.template_signals),
        (("send_file", "open(", "read_text(", "write_text("), signals.file_io_signals),
        (
            (
                "requests.",
                "httpx.",
                "fetch(",
                "axios",
                "urllib",
                "got(",
                "http.request(",
                "https.request(",
                "http.newrequest(",
                "http.newrequestwithcontext(",
                ".client.do(",
                "client.do(",
            ),
            signals.network_client_signals,
        ),
        (
            ("pickle.loads", "yaml.load", "marshal.loads", "xml.etree"),
            signals.deserialization_signals,
        ),
        (
            (
                "hashlib.md5",
                "hashlib.sha1",
                "verify=false",
                "verify = false",
                "des.new(",
                "des_ecb",
                "createcipher('des",
                'createcipher("des',
                "rc4",
            ),
            signals.crypto_signals,
        ),
        (("strcpy", "strcat", "memcpy", "malloc(", "free("), signals.native_code_signals),
        (
            ("multipart", "multer", "request.files", ".formfile(", ".parsemultipartform("),
            signals.upload_signals,
        ),
        (
            (
                "logger.",
                "logging.",
                "console.log(",
                "log.printf(",
                "log.println(",
                "logrus.",
                "slog.",
                "zap.",
                "loggerfactory.getlogger(",
            ),
            signals.logging_signals,
        ),
        (
            (
                "json.loads(",
                "json.load(",
                "json.unmarshal(",
                "objectmapper.read",
                "yaml.safe_load(",
                "yaml.unmarshal(",
                "tomllib.load",
                "toml.decode(",
                "serde_json::from_",
                "serde_yaml::from_",
                "xml.etree",
                "documentbuilderfactory",
            ),
            signals.parser_signals,
        ),
        (
            (
                "os.getenv(",
                "os.environ[",
                "process.env.",
                "system.getenv(",
                "viper.get",
                "configparser.",
                "@configurationproperties",
                "dotenv.",
                "env::var(",
                "std::env::var(",
            ),
            signals.configuration_signals,
        ),
    )
    for tokens, signal_set in signal_rules:
        if _contains_any(lower_text, tokens):
            signal_set.add(relative_path)
    if _SECRET_SIGNAL_PATTERN.search(lower_text):
        signals.secret_signals.add(relative_path)


def _record_cwe_evidence(
    lower_text: str,
    language: str,
    relative_path: str,
    signals: ProfileSignals,
) -> None:
    path_penalty = _repository_evidence_path_penalty(relative_path)
    for match in detect_cwe_evidence(lower_text, language=language):
        signals.cwe_evidence[match.cwe_id].add(f"{match.label} in {relative_path}")
        signals.cwe_evidence_files[match.cwe_id].add(relative_path)
        adjusted_score = max(1, match.score - path_penalty)
        signals.cwe_evidence_scores[match.cwe_id] = max(
            adjusted_score,
            signals.cwe_evidence_scores.get(match.cwe_id, 0),
        )


def _repository_evidence_path_penalty(relative_path: str) -> int:
    """Retain secondary code evidence without letting it dominate production source."""
    normalized = relative_path.lower()
    parts = set(Path(normalized).parts)
    file_name = Path(normalized).name
    penalty = 0
    if (
        parts & {"test", "tests", "testing", "__tests__", "fixtures", "bench", "benchmark"}
        or file_name.startswith("test_")
        or any(marker in file_name for marker in ("_test.", ".test.", ".spec.", "test.java"))
    ):
        penalty += 35
    if parts & {"example", "examples", "demo", "demos"}:
        penalty += 20
    if _is_generated_or_minified_path(parts, file_name):
        penalty += 45
    return min(penalty, 60)


def _is_generated_or_minified_path(parts: set[str], file_name: str) -> bool:
    generated_parts = {"gen", "autogen", "autogenerated", "generated"}
    generated_file_markers = (
        ".generated.",
        "-generated.",
        "_generated.",
        ".pb.cc",
        ".pb.go",
        ".pb.h",
    )
    return bool(
        parts & generated_parts
        or any(
            part.startswith(("generated-", "generated_"))
            or part.endswith(("-generated", "_generated"))
            for part in parts
        )
        or any(marker in file_name for marker in generated_file_markers)
        or ".min." in file_name
        or file_name.endswith(".map")
    )


def _read_small_text(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8")[:50_000]
    except (OSError, UnicodeDecodeError):
        return ""


def _read_manifest_text(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8")[:_MAX_PROFILE_FILE_BYTES]
    except (OSError, UnicodeDecodeError):
        return ""


def _relative_label(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _profile_confidence(
    languages: dict[str, float],
    signals: ProfileSignals,
    files: list[Path],
) -> float:
    score = 0.0
    if languages:
        score += 0.4
    if signals.frameworks:
        score += 0.25
    if signals.dependency_files:
        score += 0.2
    if files:
        score += 0.15
    return min(score, 1.0)
