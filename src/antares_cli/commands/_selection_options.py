# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared CLI parsing for repository-aware CWE selection options."""

from __future__ import annotations

from typing import cast

import typer

from antares_cli.core.cwe_selection_models import CweAbstractionLevel
from antares_cli.core.cwe_selection_scopes import ScanScope, normalize_scan_scope

VALID_CWE_LEVELS: set[str] = {"all", "pillar", "class", "base", "variant", "compound"}


def parse_scan_scope(raw_scope: str) -> ScanScope:
    try:
        return normalize_scan_scope(raw_scope)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


def parse_cwe_level(raw_level: str) -> CweAbstractionLevel:
    normalized = raw_level.strip().lower()
    if normalized not in VALID_CWE_LEVELS:
        raise typer.BadParameter("cwe-level must be all, pillar, class, base, variant, or compound")
    return cast("CweAbstractionLevel", normalized)
