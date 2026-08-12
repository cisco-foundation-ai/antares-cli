# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Canonical automatic CWE selection modes."""

from __future__ import annotations

from typing import Literal

ScanScope = Literal["auto", "top25", "owasp"]

CANONICAL_SCAN_SCOPES: tuple[ScanScope, ...] = (
    "auto",
    "top25",
    "owasp",
)
CURRENT_TOP_25_VIEW_ID = "CWE-1435"
CURRENT_OWASP_VIEW_ID = "CWE-1450"


def normalize_scan_scope(raw_scope: str) -> ScanScope:
    normalized = raw_scope.strip().lower()
    if normalized not in CANONICAL_SCAN_SCOPES:
        choices = ", ".join(CANONICAL_SCAN_SCOPES)
        raise ValueError(f"scope must be one of: {choices}")
    return normalized
