"""Thin wrapper around the Anthropic Messages API.

Handles only the API call and response mapping. Does NOT handle:
- JSON parsing (strategy's job)
- Retry logic (Session 010)
- Rate limiting (Session 010)
- Caching (Session 010)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import anthropic as _anthropic_sdk


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
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
    ) -> None:
        """Initialize the Anthropic client.

        Args:
            api_key: API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model ID to use for completions.
            max_tokens: Maximum tokens in the response.

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
        self._client = _anthropic_sdk.Anthropic(api_key=self._api_key)

    @property
    def model(self) -> str:
        """Model ID used for completions."""
        return self._model

    @property
    def max_tokens(self) -> int:
        """Maximum tokens in the response."""
        return self._max_tokens

    def complete(self, *, system: str, user: str) -> LLMResponse:
        """Send a completion request.

        Args:
            system: System prompt text.
            user: User message text.

        Returns:
            LLMResponse with raw text content.

        Raises:
            anthropic.APIError: On API communication failure.
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
