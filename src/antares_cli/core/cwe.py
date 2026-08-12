# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deterministic CWE ID normalization and validation."""

from __future__ import annotations

import re

from antares_cli.knowledge.cwe_database import CweDatabase

_CWE_STRICT_PATTERN = re.compile(r"^(?:CWE[-_\s]*)?0*(\d+)$", re.IGNORECASE)
_CWE_SEARCH_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class CweIdError(ValueError):
    """Raised when a CWE ID cannot be normalized or validated."""


def normalize_cwe_id(raw_cwe_id: str, *, strict: bool = True) -> str:
    """Normalize a CWE identifier to the canonical ``CWE-NNN`` form.

    strict=True (default): input must be a standalone CWE reference like
        "22", "cwe-22", "CWE_22". Raises CweIdError if unparseable.

    strict=False: extracts the first CWE-NNN from anywhere in the string
        (e.g. "CWE-798: Hard-coded Credentials" → "CWE-798").
        Falls back to bare-digit handling ("22" → "CWE-22").
        Returns the original string if nothing matches.
    """
    text = raw_cwe_id.strip()

    if strict:
        match = _CWE_STRICT_PATTERN.match(text)
        if match is None:
            raise CweIdError(f"Invalid CWE ID: {raw_cwe_id!r}")
        numeric_id = int(match.group(1))
        if numeric_id <= 0:
            raise CweIdError(f"Invalid CWE ID: {raw_cwe_id!r}")
        return f"CWE-{numeric_id}"

    search_match = _CWE_SEARCH_PATTERN.search(text)
    if search_match:
        return f"CWE-{int(search_match.group(1))}"
    if text.isdigit():
        return f"CWE-{int(text)}"
    return text


def normalize_cwe_ids(
    raw_cwe_ids: list[str],
    cwe_database: CweDatabase,
) -> list[str]:
    """Normalize, validate, and de-duplicate CWE IDs while preserving order."""
    normalized_ids: list[str] = []
    seen_ids: set[str] = set()
    for raw_cwe_id in raw_cwe_ids:
        normalized_id = normalize_cwe_id(raw_cwe_id)
        if cwe_database.get_by_id(normalized_id) is None:
            raise CweIdError(f"Unknown CWE ID: {normalized_id}")
        if normalized_id not in seen_ids:
            normalized_ids.append(normalized_id)
            seen_ids.add(normalized_id)
    return normalized_ids


def parse_cwe_id_list(raw_value: str | None) -> list[str]:
    """Parse a comma-separated CLI CWE list into raw ID tokens."""
    if raw_value is None:
        return []
    return [part.strip() for part in raw_value.split(",") if part.strip()]
