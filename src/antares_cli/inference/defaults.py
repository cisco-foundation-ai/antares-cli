# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Endpoint-neutral defaults for Antares model deployments."""

from __future__ import annotations

DEFAULT_ANTARES_CONTEXT_WINDOW = 16_384
DEFAULT_ANTARES_MAX_TOKENS = 4_096
DEFAULT_ANTARES_TEMPERATURE = 0.3
DEFAULT_ANTARES_TOP_P = 1.0
DEFAULT_ANTARES_FREQUENCY_PENALTY = 0.3
DEFAULT_ANTARES_STOP_TOKENS = ("<|end_of_text|>", "<|start_of_role|>")
DEFAULT_ANTARES_USE_COMPLETIONS_API = True
DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS = 300.0
