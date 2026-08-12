# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OpenAI-compatible remote inference backend."""

from __future__ import annotations

import json
import math
import random
import threading
import time
from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx

from antares_cli.inference.backend import (
    InferenceBackend,
    InferenceContextLengthError,
    InferenceStreamError,
)
from antares_cli.inference.defaults import (
    DEFAULT_ANTARES_CONTEXT_WINDOW,
    DEFAULT_ANTARES_FREQUENCY_PENALTY,
    DEFAULT_ANTARES_MAX_TOKENS,
    DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS,
    DEFAULT_ANTARES_STOP_TOKENS,
    DEFAULT_ANTARES_TEMPERATURE,
    DEFAULT_ANTARES_TOP_P,
    DEFAULT_ANTARES_USE_COMPLETIONS_API,
)
from antares_cli.inference.granite import (
    apply_granite_chat_template as _apply_granite_chat_template,
)
from antares_cli.inference.granite import prompt_token_budget

_COLD_START_RETRY_DELAY = 5.0
_COLD_START_MAX_RETRIES = 6
_MAX_RETRY_DELAY_SECONDS = 30.0
_MAX_SSE_LINE_CHARS = 1_000_000
_MAX_STREAM_CHARS = 4_000_000
_MAX_ERROR_BODY_CHARS = 16_384
_TRANSIENT_HTTP_STATUS_CODES = {404, 408, 429, 500, 502, 503, 504}
_TRANSIENT_HTTP_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
    httpx.WriteError,
    httpx.WriteTimeout,
    httpx.StreamClosed,
)


def _validate_generation_value(
    name: str,
    value: float | None,
    *,
    minimum: float,
    maximum: float | None = None,
    minimum_open: bool = False,
) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"Remote inference {name} must be numeric")
    below_minimum = value <= minimum if minimum_open else value < minimum
    if not math.isfinite(value) or below_minimum or (maximum is not None and value > maximum):
        interval_start = "greater than" if minimum_open else "at least"
        interval_end = f" and at most {maximum:g}" if maximum is not None else ""
        raise ValueError(
            f"Remote inference {name} must be finite, {interval_start} {minimum:g}{interval_end}"
        )


def _build_request_headers(api_key: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


class RemoteInferenceBackend(InferenceBackend):
    """Streams text from an OpenAI-compatible chat completions endpoint."""

    backend_name = "remote"

    def __init__(
        self,
        *,
        model_id: str,
        endpoint: str,
        context_window: int = DEFAULT_ANTARES_CONTEXT_WINDOW,
        timeout_seconds: float = DEFAULT_ANTARES_REMOTE_TIMEOUT_SECONDS,
        api_key: str | None = None,
        retry_count: int = _COLD_START_MAX_RETRIES,
        retry_delay: float = _COLD_START_RETRY_DELAY,
        max_tokens: int = DEFAULT_ANTARES_MAX_TOKENS,
        temperature: float | None = DEFAULT_ANTARES_TEMPERATURE,
        top_p: float | None = DEFAULT_ANTARES_TOP_P,
        repetition_penalty: float | None = None,
        frequency_penalty: float | None = DEFAULT_ANTARES_FREQUENCY_PENALTY,
        stop_tokens: list[str] | None = None,
        use_completions_api: bool = DEFAULT_ANTARES_USE_COMPLETIONS_API,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(model_id=model_id, context_window=context_window)
        normalized_endpoint = endpoint.strip().rstrip("/")
        parsed_endpoint = urlsplit(normalized_endpoint)
        if (
            parsed_endpoint.scheme not in {"http", "https"}
            or not parsed_endpoint.netloc
            or parsed_endpoint.username is not None
            or parsed_endpoint.password is not None
            or parsed_endpoint.query
            or parsed_endpoint.fragment
        ):
            raise ValueError(
                "Remote inference endpoint must be an HTTP(S) URL without embedded "
                "credentials, query parameters, or fragments"
            )
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("Remote inference timeout must be a finite number greater than zero")
        if isinstance(retry_count, bool) or not isinstance(retry_count, int) or retry_count < 1:
            raise ValueError("Remote inference retry count must be at least one")
        if not math.isfinite(retry_delay) or retry_delay < 0:
            raise ValueError("Remote inference retry delay must be a finite non-negative number")
        if isinstance(max_tokens, bool) or max_tokens < 1:
            raise ValueError("Remote inference max_tokens must be at least one")
        if max_tokens >= context_window:
            raise ValueError("Remote inference max_tokens must be smaller than context_window")
        prompt_token_budget(
            context_window=context_window,
            reserved_output_tokens=max_tokens,
        )
        _validate_generation_value("temperature", temperature, minimum=0.0, maximum=2.0)
        _validate_generation_value("top_p", top_p, minimum=0.0, maximum=1.0, minimum_open=True)
        _validate_generation_value(
            "repetition_penalty", repetition_penalty, minimum=0.0, minimum_open=True
        )
        _validate_generation_value(
            "frequency_penalty", frequency_penalty, minimum=-2.0, maximum=2.0
        )
        self.endpoint = normalized_endpoint
        self.timeout_seconds = timeout_seconds
        self._retry_count = retry_count
        self._retry_delay = retry_delay
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.repetition_penalty = repetition_penalty
        self.frequency_penalty = frequency_penalty
        self.stop_tokens = list(DEFAULT_ANTARES_STOP_TOKENS) if stop_tokens is None else stop_tokens
        self.use_completions_api = use_completions_api or (
            endpoint.rstrip("/").endswith("/v1/completions") and "/chat/completions" not in endpoint
        )
        self._request_headers = _build_request_headers(api_key)
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def metadata(self) -> dict[str, object]:
        base = super().metadata()
        base.update(
            {
                "endpoint": self.endpoint,
                "timeout_seconds": self.timeout_seconds,
                "retry_count": self._retry_count,
                "retry_delay": self._retry_delay,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
                "repetition_penalty": self.repetition_penalty,
            }
        )
        return base

    def stream_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        if self.use_completions_api:
            return self._completions_generate(messages)
        return self._chat_completions_generate(messages)

    def _chat_completions_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        payload: dict[str, object] = {
            "model": self.model_id,
            "messages": messages,
            "stream": True,
            "max_tokens": self.max_tokens,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.top_p is not None:
            payload["top_p"] = self.top_p
        if self.repetition_penalty is not None:
            payload["repetition_penalty"] = self.repetition_penalty
        if self.frequency_penalty is not None:
            payload["frequency_penalty"] = self.frequency_penalty
        if self.stop_tokens:
            payload["stop"] = self.stop_tokens

        url = self._resolve_url("/chat/completions")
        return self._stream_response(url, payload, content_key="delta")

    def _completions_generate(self, messages: list[dict[str, str]]) -> Iterator[str]:
        prompt = _apply_granite_chat_template(messages)
        payload: dict[str, object] = {
            "model": self.model_id,
            "prompt": prompt,
            "stream": True,
            "max_tokens": self.max_tokens,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.top_p is not None:
            payload["top_p"] = self.top_p
        if self.repetition_penalty is not None:
            payload["repetition_penalty"] = self.repetition_penalty
        if self.frequency_penalty is not None:
            payload["frequency_penalty"] = self.frequency_penalty
        if self.stop_tokens:
            payload["stop"] = self.stop_tokens

        url = self._resolve_url("/completions")
        return self._stream_response(url, payload, content_key="text")

    def _stream_response(
        self, url: str, payload: dict[str, object], *, content_key: str
    ) -> Iterator[str]:
        deadline = time.monotonic() + self.timeout_seconds
        for attempt in range(self._retry_count):
            yielded_content = False
            retry_after: float | None = None
            remaining_seconds = _remaining_seconds(deadline)
            try:
                with self._client.stream(
                    "POST",
                    url,
                    headers=self._request_headers,
                    json=payload,
                    timeout=httpx.Timeout(remaining_seconds),
                ) as response:
                    if (
                        response.status_code in _TRANSIENT_HTTP_STATUS_CODES
                        and attempt < self._retry_count - 1
                    ):
                        retry_after = _retry_after_seconds(response)
                    else:
                        if _is_context_size_rejection(response):
                            raise InferenceContextLengthError(
                                "Inference request exceeded the model context capacity."
                            )
                        response.raise_for_status()
                        deadline_timer = threading.Timer(
                            _remaining_seconds(deadline),
                            response.close,
                        )
                        deadline_timer.daemon = True
                        deadline_timer.start()
                        try:
                            for raw_line in _iter_sse_lines(response, deadline=deadline):
                                done, content = _content_from_sse_line(
                                    raw_line,
                                    content_key=content_key,
                                )
                                if done:
                                    return
                                if content is None:
                                    continue
                                yielded_content = True
                                yield content
                            _remaining_seconds(deadline)
                            raise InferenceStreamError(
                                "Inference response stream ended before completion."
                            )
                        finally:
                            deadline_timer.cancel()
            except _TRANSIENT_HTTP_ERRORS as error:
                if time.monotonic() >= deadline:
                    raise InferenceStreamError(
                        "Inference request exceeded the configured timeout."
                    ) from error
                if yielded_content:
                    raise InferenceStreamError(
                        "Inference response stream ended before completion."
                    ) from error
                if attempt >= self._retry_count - 1:
                    raise
            if attempt < self._retry_count - 1:
                delay = (
                    retry_after
                    if retry_after is not None
                    else _exponential_retry_delay(self._retry_delay, attempt)
                )
                time.sleep(min(delay, _remaining_seconds(deadline)))

    def _resolve_url(self, path: str) -> str:
        base = self.endpoint
        if base.endswith("/chat/completions"):
            base = base.removesuffix("/chat/completions")
        elif base.endswith("/v1/completions"):
            base = base.removesuffix("/v1/completions")
        elif base.endswith("/completions"):
            base = base.removesuffix("/completions")
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        return f"{base}{path}"


def _is_context_size_rejection(response: httpx.Response) -> bool:
    if response.status_code != 400:
        return False
    text = _bounded_error_text(response).lower()
    indicators = (
        "maximum context length",
        "context length exceeded",
        "context_length_exceeded",
        "max_model_len",
        "prompt is too long",
        "input is too long",
        "too many input tokens",
    )
    return any(indicator in text for indicator in indicators)


def _bounded_error_text(response: httpx.Response) -> str:
    parts: list[str] = []
    character_count = 0
    for chunk in response.iter_text():
        remaining = _MAX_ERROR_BODY_CHARS - character_count
        if remaining <= 0:
            break
        parts.append(chunk[:remaining])
        character_count += min(len(chunk), remaining)
        if len(chunk) > remaining:
            break
    return "".join(parts)


def _iter_sse_lines(response: httpx.Response, *, deadline: float) -> Iterator[str]:
    """Decode bounded SSE lines while checking a wall-clock deadline per network chunk."""
    pending_parts: list[str] = []
    pending_chars = 0
    total_chars = 0
    for chunk in response.iter_text():
        _remaining_seconds(deadline)
        total_chars += len(chunk)
        if total_chars > _MAX_STREAM_CHARS:
            raise InferenceStreamError("Inference response exceeded the streaming size limit.")
        start = 0
        while (newline_index := chunk.find("\n", start)) >= 0:
            segment = chunk[start:newline_index]
            pending_chars += len(segment)
            if pending_chars > _MAX_SSE_LINE_CHARS:
                raise InferenceStreamError("Inference response contained an oversized SSE line.")
            pending_parts.append(segment)
            raw_line = "".join(pending_parts)
            yield raw_line.rstrip("\r")
            pending_parts.clear()
            pending_chars = 0
            start = newline_index + 1
        remainder = chunk[start:]
        if remainder:
            pending_parts.append(remainder)
            pending_chars += len(remainder)
            if pending_chars > _MAX_SSE_LINE_CHARS:
                raise InferenceStreamError("Inference response contained an oversized SSE line.")
    if pending_parts:
        pending = "".join(pending_parts)
        if pending_chars > _MAX_SSE_LINE_CHARS:
            raise InferenceStreamError("Inference response contained an oversized SSE line.")
        yield pending.rstrip("\r")


def _content_from_sse_line(raw_line: str, *, content_key: str) -> tuple[bool, str | None]:
    if not raw_line or not raw_line.startswith("data:"):
        return False, None
    data = raw_line.removeprefix("data:").strip()
    if data == "[DONE]":
        return True, None
    try:
        chunk_payload = json.loads(data)
        if not isinstance(chunk_payload, dict):
            raise TypeError("SSE payload must be an object")
        if "error" in chunk_payload:
            raise InferenceStreamError("Inference endpoint reported an error while streaming.")
        choices = chunk_payload.get("choices", [])
        if not isinstance(choices, list) or not choices:
            return False, None
        choice = choices[0]
        if not isinstance(choice, dict):
            raise TypeError("SSE choice must be an object")
        if content_key == "delta":
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                raise TypeError("SSE delta must be an object")
            content = delta.get("content")
        else:
            content = choice.get(content_key)
        return False, content if isinstance(content, str) and content else None
    except (json.JSONDecodeError, TypeError) as error:
        raise InferenceStreamError(
            "Inference endpoint returned malformed streaming data."
        ) from error


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise InferenceStreamError("Inference request exceeded the configured timeout.")
    return remaining


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw_value = response.headers.get("Retry-After")
    if raw_value is None:
        return None
    try:
        value = float(raw_value)
    except ValueError:
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return min(value, _MAX_RETRY_DELAY_SECONDS)


def _exponential_retry_delay(base_delay: float, attempt: int) -> float:
    maximum = min(_MAX_RETRY_DELAY_SECONDS, base_delay * (2**attempt))
    return random.SystemRandom().uniform(0.0, maximum)
