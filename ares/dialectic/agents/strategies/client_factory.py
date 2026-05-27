"""Factory for LLM clients — dispatches on provider name.

All clients share the same complete(system, user) -> LLMResponse interface.
The measurement layer never imports a provider-specific client directly.
"""

from __future__ import annotations

from typing import Union

from ares.dialectic.agents.strategies.client import AnthropicClient, LLMResponse
from ares.dialectic.agents.strategies.openai_client import OpenAIClient
from ares.dialectic.agents.strategies.gemini_client import GeminiClient

AnyLLMClient = Union[AnthropicClient, OpenAIClient, GeminiClient]

PROVIDER_DEFAULTS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "gemini": "gemini-2.5-pro",
}

VALID_PROVIDERS: frozenset[str] = frozenset(PROVIDER_DEFAULTS.keys())


def make_client(
    provider: str,
    model: str | None = None,
    **kwargs: object,
) -> AnyLLMClient:
    """Create an LLM client for the given provider.

    Args:
        provider: One of "anthropic", "openai", "gemini".
        model: Model ID override. Uses provider default if None.
        **kwargs: Forwarded to the client constructor (api_key, max_tokens, etc.)

    Returns:
        A client with a .complete(system=..., user=...) -> LLMResponse method.
    """
    if provider not in VALID_PROVIDERS:
        raise ValueError(
            f"Unknown provider {provider!r}. Valid: {sorted(VALID_PROVIDERS)}"
        )

    resolved_model = model or PROVIDER_DEFAULTS[provider]

    if provider == "anthropic":
        return AnthropicClient(model=resolved_model, **kwargs)  # type: ignore[arg-type]
    elif provider == "openai":
        return OpenAIClient(model=resolved_model, **kwargs)  # type: ignore[arg-type]
    elif provider == "gemini":
        return GeminiClient(model=resolved_model, **kwargs)  # type: ignore[arg-type]
    else:
        raise ValueError(f"Unhandled provider: {provider!r}")


__all__ = [
    "AnyLLMClient",
    "LLMResponse",
    "make_client",
    "PROVIDER_DEFAULTS",
    "VALID_PROVIDERS",
]
