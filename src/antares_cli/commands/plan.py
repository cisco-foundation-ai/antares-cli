# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Plan command for repository-aware CWE check selection."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from antares_cli.commands._selection_options import parse_cwe_level, parse_scan_scope
from antares_cli.config import AntaresSettings
from antares_cli.core.cwe import parse_cwe_id_list
from antares_cli.core.cwe_selection import CweSelectionRequest, CweSelectionService
from antares_cli.core.cwe_selection_limits import (
    DEFAULT_AUTOMATIC_CWE_LIMIT,
    MIN_AUTOMATIC_CWE_LIMIT,
)

console = Console()

_VALID_FORMATS = {"summary", "json"}


def plan_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository directory to profile.",
    ),
    cwe: str | None = typer.Option(
        None,
        "--cwe",
        help="Comma-separated CWE IDs for exact expert-mode planning.",
    ),
    scope: str = typer.Option(
        "auto",
        "--scope",
        help="Candidate set: auto, top25, or owasp.",
    ),
    cwe_level: str = typer.Option(
        "all",
        "--cwe-level",
        help="MITRE CWE abstraction level: all, pillar, class, base, variant, or compound.",
    ),
    max_cwes: int = typer.Option(
        DEFAULT_AUTOMATIC_CWE_LIMIT,
        "--max-cwes",
        min=MIN_AUTOMATIC_CWE_LIMIT,
        help="Maximum ranked CWE targets selected automatically; ignored with --cwe.",
    ),
    output_format: str = typer.Option(
        "summary",
        "--format",
        help="Plan output format: summary or json.",
    ),
) -> None:
    """Show selected CWE-backed checks without running a scan."""
    try:
        settings = AntaresSettings.load(start_path=path)
        plan = CweSelectionService().select(
            CweSelectionRequest(
                target=path,
                cwe_ids=parse_cwe_id_list(cwe),
                ignore_paths=tuple(settings.ignore_paths),
                scope=parse_scan_scope(scope),
                cwe_level=parse_cwe_level(cwe_level),
                max_cwes=max_cwes,
            )
        )
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    if output_format not in _VALID_FORMATS:
        raise typer.BadParameter("format must be summary or json")
    if output_format == "json":
        typer.echo(json.dumps(plan.to_dict(), indent=2))
        return
    _render_plan_summary(plan.to_dict())


def _render_plan_summary(plan_payload: dict[str, object]) -> None:
    intent = plan_payload["intent"]
    if not isinstance(intent, dict):
        raise TypeError("plan intent must be a dictionary")
    selected_cwe_ids = plan_payload["selected_cwe_ids"]
    if not isinstance(selected_cwe_ids, list):
        raise TypeError("selected_cwe_ids must be a list")

    console.print(
        "antares plan: "
        f"{intent['mode']} {intent['scope']} {intent['cwe_level']} "
        f"({len(selected_cwe_ids)} CWE scan targets)",
        markup=False,
    )
    if intent["mode"] == "auto":
        candidate_count = _required_plan_int(plan_payload, "candidate_cwe_count")
        omitted_count = _required_plan_int(plan_payload, "omitted_candidate_count")
        automatic_limit = _required_plan_int(plan_payload, "automatic_limit")
        console.print(
            f"Automatic selection: {len(selected_cwe_ids)} of {candidate_count} eligible CWE "
            f"candidates (limit {automatic_limit}; {omitted_count} omitted)."
        )
        priority_baseline = plan_payload["priority_baseline"]
        if isinstance(priority_baseline, dict):
            console.print(
                f"Priority baseline: {priority_baseline['selected_count']} of "
                f"{priority_baseline['eligible_count']} eligible "
                f"{priority_baseline['name']} entries selected."
            )
        elif priority_baseline is not None:
            raise TypeError("priority_baseline must be a dictionary or null")
        tier_counts = plan_payload.get("selection_tier_counts")
        if isinstance(tier_counts, dict):
            console.print(f"Portfolio: {_selection_tier_summary(tier_counts)}.", markup=False)
    selection_notes = plan_payload["selection_notes"]
    if not isinstance(selection_notes, list):
        raise TypeError("selection_notes must be a list")
    console.print(f"Policy: {plan_payload['selection_policy']}", markup=False)
    taxonomy = plan_payload.get("taxonomy")
    if isinstance(taxonomy, dict):
        console.print(
            f"Taxonomy: {taxonomy['catalog']} {taxonomy['version']} "
            f"({taxonomy['release_date']}; {taxonomy['entry_count']} weaknesses)"
        )
    for note in selection_notes:
        console.print(f"  - {note}", markup=False)
    selected_checks = plan_payload["selected_checks"]
    if not isinstance(selected_checks, list):
        raise TypeError("selected_checks must be a list")
    for raw_check in selected_checks:
        if isinstance(raw_check, dict):
            _print_check_summary(raw_check)


def _required_plan_int(plan_payload: dict[str, object], key: str) -> int:
    value = plan_payload[key]
    if not isinstance(value, int):
        raise TypeError(f"plan {key} must be an integer")
    return value


def _selection_tier_summary(tier_counts: dict[object, object]) -> str:
    ordered_tiers = ("repository-specific", "priority-baseline", "ranked-fill")
    return ", ".join(
        f"{tier_counts.get(tier, 0)} {tier}" for tier in ordered_tiers if tier in tier_counts
    )


def _print_check_summary(check: dict[object, object]) -> None:
    cwe_ids = check.get("cwe_ids", [])
    reasons = check.get("reasons", [])
    cwe_text = ", ".join(str(cwe_id) for cwe_id in cwe_ids) if isinstance(cwe_ids, list) else ""
    reason_text = "; ".join(str(reason) for reason in reasons) if isinstance(reasons, list) else ""
    console.print(
        f"- [bold]{escape(str(check.get('title', '')))}[/bold] "
        f"({escape(cwe_text)}, score {escape(str(check.get('score', '')))}, "
        f"tier {check.get('selection_tier', '')})"
    )
    console.print(f"  Plain English: {check.get('plain_language_summary', '')}", markup=False)
    console.print(f"  Why it matters: {check.get('why_it_matters', '')}", markup=False)
    console.print(f"  Selected because: {reason_text}", markup=False)
