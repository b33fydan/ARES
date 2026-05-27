"""Google Gemini client implementing the same complete() interface as AnthropicClient.

Shares the LLMResponse dataclass so the measurement layer stays model-agnostic.
Uses the current google.genai SDK (not the deprecated google.generativeai).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

from google import genai
from google.genai import types

from ares.dialectic.agents.strategies.client import LLMResponse

logger = logging.getLogger("ares.llm.gemini_client")

DEFAULT_GEMINI_MODEL: str = "gemini-2.5-pro"


class GeminiClient:
    """Thin wrapper around the Google Gemini API."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: str = DEFAULT_GEMINI_MODEL,
        max_tokens: int = 4096,
        max_retries: int = 3,
        base_retry_delay: float = 1.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self._api_key:
            raise ValueError(
                "GOOGLE_API_KEY required (pass directly or set env var)"
            )
        self._model_name = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_retry_delay = base_retry_delay
        self._client = genai.Client(api_key=self._api_key)

    @property
    def model(self) -> str:
        return self._model_name

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
        response = self._client.models.generate_content(
            model=self._model_name,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                max_output_tokens=self._max_tokens,
            ),
        )
        usage = response.usage_metadata
        return LLMResponse(
            content=response.text or "",
            model=self._model_name,
            usage_input_tokens=usage.prompt_token_count if usage else 0,
            usage_output_tokens=usage.candidates_token_count if usage else 0,
        )

    @staticmethod
    def _is_retryable(error: Exception) -> bool:
        if isinstance(error, (ConnectionError, TimeoutError)):
            return True
        error_str = str(error).lower()
        if "rate" in error_str and "limit" in error_str:
            return True
        if "503" in error_str or "500" in error_str:
            return True
        return False
