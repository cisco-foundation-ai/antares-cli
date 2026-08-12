# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared color palette and styling constants for the antares TUI."""

from __future__ import annotations

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff3333",
    "high": "#ff6666",
    "medium": "#ffaa00",
    "low": "#44cccc",
    "info": "#888888",
}

CHROME_DIM = "#555555"
ACCENT = "#44bbdd"
ACCENT_BOLD = "#66ddff"
SUCCESS = "#44cc66"
ACTIVITY_COMMAND = "#ffffff"
ACTIVITY_RESULT = "#777777"
ACTIVITY_THINKING = "#aa88cc"
WORKER_DONE = "#44cc66"
WORKER_RUNNING = "#ffaa00"
WORKER_QUEUED = "#555555"
