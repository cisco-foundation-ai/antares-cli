# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared concurrency limits for CWE sweep workers."""

from __future__ import annotations

DEFAULT_SWEEP_WORKERS = 8
MAX_SWEEP_WORKERS = 32


def resolve_sweep_worker_count(value: object) -> int:
    """Validate a worker count at public and internal service boundaries."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("workers must be an integer")
    if value < 1 or value > MAX_SWEEP_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_SWEEP_WORKERS}")
    return value
