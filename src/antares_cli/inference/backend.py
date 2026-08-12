# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inference backend abstractions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from antares_cli.inference.defaults import DEFAULT_ANTARES_CONTEXT_WINDOW


class InferenceError(RuntimeError):
    """Raised when the inference backend fails with a non-recoverable error (auth, connection, timeout)."""


class InferenceStreamError(InferenceError):
    """Raised when a response stream is incomplete or violates the backend protocol."""


class InferenceContextLengthError(InferenceError):
    """Raised when the endpoint explicitly rejects an oversized model prompt."""


class InferenceBackend(ABC):
    """Abstract inference backend."""

    backend_name = "base"

    def __init__(
        self,
        *,
        model_id: str,
        context_window: int = DEFAULT_ANTARES_CONTEXT_WINDOW,
    ) -> None:
        self.model_id = normalize_model_id(model_id)
        if isinstance(context_window, bool) or not isinstance(context_window, int):
            raise ValueError("Model context_window must be an integer")
        if context_window < 1_024:
            raise ValueError("Model context_window must be at least 1024 tokens")
        self.context_window = context_window

    @abstractmethod
    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        """Yield generated text chunks."""

    def close(self) -> None:
        """Release backend resources. Stateless backends have nothing to close."""
        return None

    def metadata(self) -> dict[str, object]:
        """Return backend configuration for run history/tracing. Override to add fields."""
        return {
            "class": self.__class__.__name__,
            "backend_name": self.backend_name,
            "model_id": self.model_id,
            "context_window": self.context_window,
        }


def normalize_model_id(model_id: str) -> str:
    """Normalize a model ID string. Accepts any user-provided identifier."""
    normalized = model_id.strip()
    if not normalized:
        raise ValueError("Model ID must not be empty")
    return normalized
