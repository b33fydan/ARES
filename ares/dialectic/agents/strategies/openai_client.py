"""OpenAI client implementing the same complete() interface as AnthropicClient.

Shares the LLMResponse dataclass so the measurement layer stays model-agnostic.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import openai as _openai_sdk

from ares.dialectic.agents.strategies.client import LLMResponse

logger = logging.getLogger("ares.llm.openai_client")

DEFAULT_OPENAI_MODEL: str = "gpt-4o"


class OpenAIClient:
    """Thin wrapper around the OpenAI Chat Completions API."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: str = DEFAULT_OPENAI_MODEL,
        max_tokens: int = 4096,
        max_retries: int = 3,
        base_retry_delay: float = 1.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError(
                "OPENAI_API_KEY required (pass directly or set env var)"
            )
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_retry_delay = base_retry_delay
        self._client = _openai_sdk.OpenAI(api_key=self._api_key)

    @property
    def model(self) -> str:
        return self._model

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def max_retries(self) -> int:
        return self._max_retries

    @property
    def base_retry_delay(self) -> float:
        return self._base_retry_delay

    def complete(self, *, system: str, user: str) -> LLMResponse:
        last_exception: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                return self._do_complete(system=system, user=user)
            except Exception as e:
                last_exception = e
                if attempt < self._max_retries and self._is_retryable(e):
                    delay = self._base_retry_delay * (2 ** attempt)
                    logger.warning(
                        f"Retry {attempt + 1}/{self._max_retries} "
                        f"after {delay:.1f}s: {e}"
                    )
                    time.sleep(delay)
                else:
                    raise
        raise last_exception  # type: ignore[misc]

    def _do_complete(self, *, system: str, user: str) -> LLMResponse:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = response.choices[0]
        usage = response.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            usage_input_tokens=usage.prompt_tokens if usage else 0,
            usage_output_tokens=usage.completion_tokens if usage else 0,
        )

    @staticmethod
    def _is_retryable(error: Exception) -> bool:
        if isinstance(error, _openai_sdk.RateLimitError):
            return True
        if isinstance(error, _openai_sdk.InternalServerError):
            return True
        if isinstance(error, _openai_sdk.APIConnectionError):
            return True
        if isinstance(error, (ConnectionError, TimeoutError)):
            return True
        return False
