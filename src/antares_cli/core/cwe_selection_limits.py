# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared limits for repository-aware automatic CWE selection."""

from __future__ import annotations

DEFAULT_AUTOMATIC_CWE_LIMIT = 50
MIN_AUTOMATIC_CWE_LIMIT = 1


def resolve_automatic_cwe_limit(value: int | None) -> int:
    limit = DEFAULT_AUTOMATIC_CWE_LIMIT if value is None else value
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("max_cwes must be an integer")
    if limit < MIN_AUTOMATIC_CWE_LIMIT:
        raise ValueError(f"max_cwes must be at least {MIN_AUTOMATIC_CWE_LIMIT}")
    return limit
