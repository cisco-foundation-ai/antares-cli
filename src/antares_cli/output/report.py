# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Report serialization utilities."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote

from antares_cli.knowledge.cwe_database import CweDatabase
from antares_cli.output.finding import Finding, ReportSummary, deduplicate_findings

OutputFormat = Literal["json", "markdown", "sarif"]

REPORT_FORMATS: tuple[OutputFormat, ...] = ("json", "markdown", "sarif")
_VALID_FORMATS: set[str] = set(REPORT_FORMATS)


def normalize_output_format(output_format: str | None) -> OutputFormat | None:
    """Validate and normalize a user-provided output format string."""
    if output_format is None:
        return None
    normalized = output_format.lower()
    if normalized not in _VALID_FORMATS:
        raise ValueError(f"Output format must be json, markdown, or sarif (got: {output_format!r})")
    return cast(OutputFormat, normalized)


def normalize_report_formats(
    output_formats: list[str] | tuple[str, ...],
) -> tuple[OutputFormat, ...]:
    """Validate requested artifact formats, defaulting to the complete report bundle."""
    if not output_formats:
        return REPORT_FORMATS
    requested_all = False
    normalized_formats: list[OutputFormat] = []
    for output_format in output_formats:
        if output_format.lower() == "all":
            requested_all = True
            continue
        try:
            normalized_format = normalize_output_format(output_format)
        except ValueError as error:
            raise ValueError(
                f"Report format must be json, markdown, sarif, or all (got: {output_format!r})"
            ) from error
        if normalized_format is not None and normalized_format not in normalized_formats:
            normalized_formats.append(normalized_format)
    return REPORT_FORMATS if requested_all else tuple(normalized_formats)


def serialize_report_json(
    findings: list[Finding],
    summary: ReportSummary,
    *,
    per_cwe_results: list[dict[str, Any]] | None = None,
) -> str:
    payload: dict[str, object] = {
        "summary": summary.to_public_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    if per_cwe_results is not None:
        payload["per_cwe_results"] = public_per_cwe_results(per_cwe_results)
    warnings = _summary_warnings(summary)
    if warnings:
        payload["warnings"] = warnings
    return json.dumps(payload, indent=2)


def serialize_report_markdown(
    findings: list[Finding],
    summary: ReportSummary,
    *,
    per_cwe_results: list[dict[str, Any]] | None = None,
    checked_cwe_ids: list[str] | None = None,
) -> str:
    affected_file_count = len({finding.file_path for finding in findings})
    checked_cwe_count = (
        len(per_cwe_results or [])
        or len(checked_cwe_ids or [])
        or summary.total_workers
        or len(summary.cwe_ids_triggered)
    )
    status = "Incomplete" if _summary_warnings(summary) else "Complete"
    lines = [
        "# Antares Security Report",
        "",
        "## Summary",
        "",
        f"- Status: {status}",
        f"- Findings: {summary.total_findings}",
        f"- Affected files: {affected_file_count}",
        f"- CWEs checked: {checked_cwe_count}",
        f"- CWEs with findings: {len(summary.cwe_ids_triggered)}",
        f"- Duration: {summary.duration_seconds:.2f}s",
    ]
    warnings = _summary_warnings(summary)
    if warnings:
        lines.append("")
        lines.append("**⚠ Warnings:**")
        for warning in warnings:
            lines.append(f"- {warning}")
    lines.append("")
    lines.append("## Findings by file")
    lines.append("")
    if not findings:
        lines.append("No findings were reported.")
    else:
        findings_by_file: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            findings_by_file[finding.file_path].append(finding)
        for file_path in sorted(findings_by_file):
            file_findings = findings_by_file[file_path]
            finding_label = "finding" if len(file_findings) == 1 else "findings"
            lines.extend(
                [
                    f"### {_markdown_code(file_path)} — {len(file_findings)} {finding_label}",
                    "",
                ]
            )
            findings_by_cwe: dict[str, list[Finding]] = defaultdict(list)
            for finding in file_findings:
                primary_cwe = finding.cwe_ids[0] if finding.cwe_ids else ""
                findings_by_cwe[primary_cwe].append(finding)
            for primary_cwe in sorted(findings_by_cwe, key=_cwe_sort_key):
                cwe_heading = _cwe_label(primary_cwe) if primary_cwe else "Unclassified"
                lines.extend([f"#### {_markdown_text(cwe_heading)}", ""])
                for finding in sorted(
                    findings_by_cwe[primary_cwe],
                    key=lambda item: (
                        item.submission_rank is None,
                        item.submission_rank or 0,
                        item.title,
                    ),
                ):
                    lines.extend([f"##### {_markdown_text(finding.title)}", ""])
                    if len(finding.cwe_ids) > 1:
                        related_cwes = ", ".join(
                            _markdown_text(_cwe_label(cwe_id)) for cwe_id in finding.cwe_ids[1:]
                        )
                        lines.append(f"- Related CWEs: {related_cwes}")
                    if finding.submission_rank is not None:
                        lines.append(f"- Submission rank: {finding.submission_rank}")
                    if finding.likelihood_of_exploit:
                        lines.append(
                            f"- Likelihood of exploit: "
                            f"{_markdown_text(finding.likelihood_of_exploit)}"
                        )
                    lines.append("")

    coverage_results = list(per_cwe_results or [])
    if not coverage_results and checked_cwe_ids:
        coverage_results = [
            {
                "cwe_id": cwe_id,
                "finding_count": sum(cwe_id in finding.cwe_ids for finding in findings),
            }
            for cwe_id in checked_cwe_ids
        ]
    if coverage_results:
        lines.extend(["## Scan coverage", "", "| CWE | Outcome |", "| --- | --- |"])
        for entry in coverage_results:
            cwe_id = entry.get("cwe_id")
            cwe_label = _cwe_label(cwe_id) if isinstance(cwe_id, str) else "Unknown"
            error_message = entry.get("error_message")
            finding_count = entry.get("finding_count", 0)
            if isinstance(error_message, str) and error_message:
                outcome = f"Failed — {error_message}"
            elif isinstance(finding_count, int) and finding_count > 0:
                suffix = "finding" if finding_count == 1 else "findings"
                outcome = f"{finding_count} {suffix}"
            else:
                outcome = "No findings reported"
            lines.append(f"| {_markdown_text(cwe_label)} | {_markdown_text(outcome)} |")
        lines.append("")

    lines.extend(
        [
            "## Scan details",
            "",
            f"- Total tool calls: {summary.tool_call_count}",
            f"- Failed tool calls: {summary.failed_tool_calls}",
            f"- Retried turns: {summary.retried_turns}",
        ]
    )
    return "\n".join(lines)


def serialize_report_sarif(
    findings: list[Finding],
    summary: ReportSummary,
    *,
    per_cwe_results: list[dict[str, Any]] | None = None,
) -> str:
    unique_cwe_ids = sorted({cwe for finding in findings for cwe in finding.cwe_ids})
    rules = [
        {
            "id": cwe_id,
            "name": _cwe_name(cwe_id) or cwe_id,
            "shortDescription": {"text": _cwe_label(cwe_id)},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html",
            "properties": {"tags": ["security"]},
        }
        for cwe_id in unique_cwe_ids
    ]

    results = []
    for finding in sorted(
        findings,
        key=lambda item: (
            item.file_path,
            item.cwe_ids[0] if item.cwe_ids else "",
            item.submission_rank is None,
            item.submission_rank or 0,
            item.title,
        ),
    ):
        properties: dict[str, object] = {
            "title": finding.title,
            "cweIds": finding.cwe_ids,
            "likelihoodOfExploit": finding.likelihood_of_exploit,
        }
        result_entry: dict[str, object] = {
            "ruleId": finding.cwe_ids[0] if finding.cwe_ids else "ANTARES-GENERIC",
            "level": "note",
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(finding.file_path)},
                    },
                },
            ],
            "properties": properties,
        }
        if finding.submission_rank is not None:
            properties["submissionRank"] = finding.submission_rank
        results.append(result_entry)

    invocation_properties: dict[str, object] = summary.to_public_dict()
    if per_cwe_results is not None:
        invocation_properties["per_cwe_results"] = public_per_cwe_results(per_cwe_results)

    sarif_payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "antares-cli",
                        "rules": rules,
                    },
                },
                "invocations": [
                    {
                        "executionSuccessful": summary.generation_errors == 0
                        and summary.failed_workers == 0
                        and summary.incomplete_reason is None,
                        "properties": invocation_properties,
                    },
                ],
                "results": results,
            },
        ],
    }
    return json.dumps(sarif_payload, indent=2, sort_keys=True)


def write_report(
    output_path: Path,
    findings: list[Finding],
    summary: ReportSummary,
    *,
    output_format: OutputFormat | None = None,
    per_cwe_results: list[dict[str, Any]] | None = None,
    checked_cwe_ids: list[str] | None = None,
) -> Path:
    deduped_findings = deduplicate_findings(findings)

    deduped_summary = ReportSummary(
        total_findings=len(deduped_findings),
        tool_call_count=summary.tool_call_count,
        duration_seconds=summary.duration_seconds,
        investigation_trace=summary.investigation_trace,
        cwe_ids_triggered=sorted({cwe for f in deduped_findings for cwe in f.cwe_ids}),
        failed_tool_calls=summary.failed_tool_calls,
        retried_turns=summary.retried_turns,
        generation_errors=summary.generation_errors,
        failed_workers=summary.failed_workers,
        total_workers=summary.total_workers,
        incomplete_reason=summary.incomplete_reason,
    )

    resolved_format = output_format or infer_output_format(output_path)
    if resolved_format == "json":
        report_text = serialize_report_json(
            deduped_findings,
            deduped_summary,
            per_cwe_results=per_cwe_results,
        )
    elif resolved_format == "markdown":
        report_text = serialize_report_markdown(
            deduped_findings,
            deduped_summary,
            per_cwe_results=per_cwe_results,
            checked_cwe_ids=checked_cwe_ids,
        )
    elif resolved_format == "sarif":
        report_text = serialize_report_sarif(
            deduped_findings,
            deduped_summary,
            per_cwe_results=per_cwe_results,
        )
    else:
        raise ValueError(f"Unsupported output format: {resolved_format}")

    return write_report_text(output_path, report_text)


def write_report_text(output_path: Path, report_text: str) -> Path:
    """Atomically write a potentially sensitive report with private permissions."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(report_text)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        temporary_path.chmod(0o600)
        os.replace(temporary_path, output_path)
        output_path.chmod(0o600)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output_path


def infer_output_format(output_path: Path) -> OutputFormat:
    suffix = output_path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".sarif"}:
        return "sarif"
    return "json"


def _summary_warnings(summary: ReportSummary) -> list[str]:
    warnings: list[str] = []
    if getattr(summary, "generation_errors", 0) > 0:
        warnings.append(
            f"Model backend error interrupted the scan ({summary.generation_errors} error(s)); "
            "results may be incomplete"
        )
    if getattr(summary, "failed_workers", 0) > 0:
        warnings.append(
            f"{summary.failed_workers}/{summary.total_workers} CWE workers failed; "
            "some vulnerability classes were not scanned"
        )
    if summary.incomplete_reason is not None:
        warnings.append(summary.incomplete_reason)
    return warnings


def public_per_cwe_results(
    per_cwe_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove local trace paths from report and automation payloads."""
    return [
        {key: value for key, value in entry.items() if key != "investigation_trace"}
        for entry in per_cwe_results
    ]


def _markdown_code(value: str) -> str:
    normalized = _visible_control_characters(value)
    longest_run = max((len(run) for run in re.findall(r"`+", normalized)), default=0)
    fence = "`" * (longest_run + 1)
    return f"{fence}{normalized}{fence}"


def _markdown_text(value: str) -> str:
    normalized = _visible_control_characters(value)
    return re.sub(r"([\\`*{}\[\]()#+.!_|<>-])", r"\\\1", normalized)


def _cwe_label(cwe_id: str) -> str:
    name = _cwe_name(cwe_id)
    return f"{cwe_id} — {name}" if name else cwe_id


@lru_cache(maxsize=1)
def _cwe_names() -> dict[str, str]:
    return {entry.id: entry.name for entry in CweDatabase.load_default().list_all()}


def _cwe_name(cwe_id: str) -> str | None:
    return _cwe_names().get(cwe_id)


def _cwe_sort_key(cwe_id: str) -> tuple[int, str]:
    try:
        return (int(cwe_id.removeprefix("CWE-")), cwe_id)
    except ValueError:
        return (10_000, cwe_id)


def _visible_control_characters(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\n":
            escaped.append(r"\n")
        elif character == "\r":
            escaped.append(r"\r")
        elif character == "\t":
            escaped.append(r"\t")
        elif codepoint < 32 or codepoint == 127:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _sarif_uri(file_path: str) -> str:
    return quote(file_path.replace("\\", "/"), safe="/-._~:@")
