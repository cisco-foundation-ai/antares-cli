# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Terminal capability checks shared by interactive command surfaces."""

from __future__ import annotations

import sys
from typing import TextIO


def can_interact(
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> bool:
    """Return whether both input and output are attached to real terminals."""
    input_stream = stdin or sys.stdin
    output_stream = stdout or sys.stdout
    return input_stream.isatty() and output_stream.isatty()
