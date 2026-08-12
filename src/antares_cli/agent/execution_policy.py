# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared execution policy for every Antares agent entry point."""

from __future__ import annotations

DEFAULT_TERMINAL_CALL_BUDGET = 15
MIN_TERMINAL_CALL_BUDGET = 1
MAX_TERMINAL_CALL_BUDGET = 50


def resolve_terminal_call_budget(value: int | None) -> int:
    """Return the terminal-call budget used by all invocation surfaces."""
    if value is None:
        return DEFAULT_TERMINAL_CALL_BUDGET
    if not MIN_TERMINAL_CALL_BUDGET <= value <= MAX_TERMINAL_CALL_BUDGET:
        raise ValueError(
            "Terminal call budget must be between "
            f"{MIN_TERMINAL_CALL_BUDGET} and {MAX_TERMINAL_CALL_BUDGET}."
        )
    return value
