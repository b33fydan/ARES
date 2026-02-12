"""Tests for AnthropicClient and LLMResponse.

Tests focus on construction, configuration, and error handling.
Actual API calls are NOT made — the client is tested with mocks.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from ares.dialectic.agents.strategies.client import AnthropicClient, LLMResponse


class TestLLMResponse:
    """Tests for the LLMResponse frozen dataclass."""

    def test_llm_response_is_frozen(self):
        """LLMResponse is immutable."""
        resp = LLMResponse(
            content="test",
            model="claude-sonnet-4-20250514",
            usage_input_tokens=10,
            usage_output_tokens=5,
        )
        with pytest.raises(AttributeError):
            resp.content = "modified"

    def test_llm_response_stores_all_fields(self):
        """LLMResponse stores all fields correctly."""
        resp = LLMResponse(
            content="hello world",
            model="claude-sonnet-4-20250514",
            usage_input_tokens=100,
            usage_output_tokens=50,
        )
        assert resp.content == "hello world"
        assert resp.model == "claude-sonnet-4-20250514"
        assert resp.usage_input_tokens == 100
        assert resp.usage_output_tokens == 50

    def test_llm_response_equality(self):
        """LLMResponse instances with same data are equal."""
        r1 = LLMResponse("a", "m", 1, 2)
        r2 = LLMResponse("a", "m", 1, 2)
        assert r1 == r2


class TestAnthropicClientConstruction:
    """Tests for AnthropicClient construction and configuration."""

    def test_requires_api_key(self):
        """Raises ValueError when no API key is provided."""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure ANTHROPIC_API_KEY is not set
            env = os.environ.copy()
            env.pop("ANTHROPIC_API_KEY", None)
            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(ValueError, match="ANTHROPIC_API_KEY required"):
                    AnthropicClient()

    def test_accepts_api_key_via_parameter(self):
        """Accepts API key passed directly."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            client = AnthropicClient(api_key="test-key-123")
            assert client._api_key == "test-key-123"

    def test_reads_api_key_from_env(self):
        """Falls back to ANTHROPIC_API_KEY environment variable."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key-456"}):
            with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
                client = AnthropicClient()
                assert client._api_key == "env-key-456"

    def test_parameter_overrides_env(self):
        """Direct parameter overrides environment variable."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
                client = AnthropicClient(api_key="param-key")
                assert client._api_key == "param-key"

    def test_default_model(self):
        """Default model is claude-sonnet-4-20250514."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            client = AnthropicClient(api_key="test-key")
            assert client.model == "claude-sonnet-4-20250514"

    def test_default_max_tokens(self):
        """Default max_tokens is 4096."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            client = AnthropicClient(api_key="test-key")
            assert client.max_tokens == 4096

    def test_custom_model(self):
        """Custom model is accepted."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            client = AnthropicClient(api_key="test-key", model="claude-opus-4-6")
            assert client.model == "claude-opus-4-6"

    def test_custom_max_tokens(self):
        """Custom max_tokens is accepted."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            client = AnthropicClient(api_key="test-key", max_tokens=8192)
            assert client.max_tokens == 8192

    def test_complete_calls_sdk(self):
        """complete() calls the anthropic SDK correctly."""
        with patch("ares.dialectic.agents.strategies.client._anthropic_sdk") as mock_sdk:
            mock_message = mock_sdk.Anthropic.return_value.messages.create.return_value
            mock_message.content = [type("Block", (), {"text": "response text"})()]
            mock_message.model = "claude-sonnet-4-20250514"
            mock_message.usage = type("Usage", (), {"input_tokens": 10, "output_tokens": 5})()

            client = AnthropicClient(api_key="test-key")
            result = client.complete(system="sys prompt", user="user msg")

            assert result.content == "response text"
            assert result.model == "claude-sonnet-4-20250514"
            assert result.usage_input_tokens == 10
            assert result.usage_output_tokens == 5
