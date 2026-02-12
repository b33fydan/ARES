"""Thin wrapper around the Anthropic Messages API.

Handles the API call, response mapping, and retry logic for transient failures.
Does NOT handle:
- JSON parsing (strategy's job)
- Caching (future)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import anthropic as _anthropic_sdk

logger = logging.getLogger("ares.llm.client")


@dataclass(frozen=True)
class LLMResponse:
    """Raw response from the LLM.

    Immutable container for the API response. The strategy classes
    handle parsing the content field.

    Attributes:
        content: Raw text content from the LLM
        model: Model ID that generated the response
        usage_input_tokens: Number of input tokens consumed
        usage_output_tokens: Number of output tokens generated
    """

    content: str
    model: str
    usage_input_tokens: int
    usage_output_tokens: int


class AnthropicClient:
    """Thin wrapper around the Anthropic Messages API.

    Sends completion requests and returns raw text responses.
    The strategy classes handle all parsing and validation.
    Includes retry with exponential backoff for transient failures.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        max_retries: int = 3,
        base_retry_delay: float = 1.0,
    ) -> None:
        """Initialize the Anthropic client.

        Args:
            api_key: API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model ID to use for completions.
            max_tokens: Maximum tokens in the response.
            max_retries: Maximum number of retry attempts for transient failures.
            base_retry_delay: Base delay in seconds for exponential backoff.

        Raises:
            ValueError: If no API key is provided or found in environment.
        """
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY required (pass directly or set env var)"
            )
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_retry_delay = base_retry_delay
        self._client = _anthropic_sdk.Anthropic(api_key=self._api_key)

    @property
    def model(self) -> str:
        """Model ID used for completions."""
        return self._model

    @property
    def max_tokens(self) -> int:
        """Maximum tokens in the response."""
        return self._max_tokens

    @property
    def max_retries(self) -> int:
        """Maximum number of retry attempts."""
        return self._max_retries

    @property
    def base_retry_delay(self) -> float:
        """Base delay in seconds for exponential backoff."""
        return self._base_retry_delay

    def complete(self, *, system: str, user: str) -> LLMResponse:
        """Send a completion request with retry on transient failures.

        Args:
            system: System prompt text.
            user: User message text.

        Returns:
            LLMResponse with raw text content.

        Raises:
            anthropic.APIError: On non-retryable API failure, or after
                all retry attempts are exhausted.
        """
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
        raise last_exception  # Safety net — should not reach here

    def _do_complete(self, *, system: str, user: str) -> LLMResponse:
        """Execute a single API call without retry.

        Args:
            system: System prompt text.
            user: User message text.

        Returns:
            LLMResponse with raw text content.
        """
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return LLMResponse(
            content=message.content[0].text,
            model=message.model,
            usage_input_tokens=message.usage.input_tokens,
            usage_output_tokens=message.usage.output_tokens,
        )

    @staticmethod
    def _is_retryable(error: Exception) -> bool:
        """Determine if an error is transient and worth retrying.

        Retries on: rate limits, server errors, connection errors.
        Does NOT retry on: auth errors, invalid request, bad API key.

        Args:
            error: The exception to evaluate.

        Returns:
            True if the error is transient and worth retrying.
        """
        if isinstance(error, _anthropic_sdk.RateLimitError):
            return True
        if isinstance(error, _anthropic_sdk.InternalServerError):
            return True
        if isinstance(error, _anthropic_sdk.APIConnectionError):
            return True
        if isinstance(error, (ConnectionError, TimeoutError)):
            return True
        return False
