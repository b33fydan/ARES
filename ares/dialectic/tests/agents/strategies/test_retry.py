"""Tests for AnthropicClient retry logic.

All tests mock only the Anthropic client class, NOT the entire SDK module.
This preserves real exception types for isinstance checks in _is_retryable.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import anthropic
import pytest

from ares.dialectic.agents.strategies.client import AnthropicClient, LLMResponse


def _make_client(**kwargs) -> AnthropicClient:
    """Create an AnthropicClient with mocked Anthropic class."""
    with patch("ares.dialectic.agents.strategies.client._anthropic_sdk.Anthropic"):
        return AnthropicClient(api_key="test-key", **kwargs)


def _make_mock_response():
    """Create a mock API response object."""
    msg = MagicMock()
    msg.content = [MagicMock(text="response text")]
    msg.model = "claude-sonnet-4-20250514"
    msg.usage = MagicMock(input_tokens=10, output_tokens=5)
    return msg


def _make_mock_http_response(status_code: int = 429):
    """Create a mock httpx response for exception constructors."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    resp.is_closed = True
    resp.request = MagicMock()
    return resp


class TestRetryDefaults:
    """Tests for default retry configuration."""

    def test_default_max_retries(self):
        """Default max_retries is 3."""
        client = _make_client()
        assert client.max_retries == 3

    def test_default_base_retry_delay(self):
        """Default base_retry_delay is 1.0."""
        client = _make_client()
        assert client.base_retry_delay == 1.0

    def test_custom_max_retries(self):
        """Custom max_retries is accepted."""
        client = _make_client(max_retries=5)
        assert client.max_retries == 5

    def test_custom_base_retry_delay(self):
        """Custom base_retry_delay is accepted."""
        client = _make_client(base_retry_delay=0.5)
        assert client.base_retry_delay == 0.5


class TestRetryBehavior:
    """Tests for retry logic on transient failures."""

    def test_no_retry_when_max_retries_zero(self):
        """AnthropicClient with max_retries=0 does not retry."""
        client = _make_client(max_retries=0)
        error = anthropic.RateLimitError(
            "rate limited",
            response=_make_mock_http_response(429),
            body=None,
        )
        client._client.messages.create.side_effect = error
        with pytest.raises(anthropic.RateLimitError):
            client.complete(system="sys", user="usr")
        assert client._client.messages.create.call_count == 1

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_on_rate_limit_error(self, mock_sleep):
        """AnthropicClient retries on RateLimitError."""
        client = _make_client(base_retry_delay=0.01)
        error = anthropic.RateLimitError(
            "rate limited",
            response=_make_mock_http_response(429),
            body=None,
        )
        success = _make_mock_response()
        client._client.messages.create.side_effect = [error, success]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"
        assert mock_sleep.called

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_on_internal_server_error(self, mock_sleep):
        """AnthropicClient retries on InternalServerError."""
        client = _make_client(base_retry_delay=0.01)
        error = anthropic.InternalServerError(
            "server error",
            response=_make_mock_http_response(500),
            body=None,
        )
        success = _make_mock_response()
        client._client.messages.create.side_effect = [error, success]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_on_api_connection_error(self, mock_sleep):
        """AnthropicClient retries on APIConnectionError."""
        client = _make_client(base_retry_delay=0.01)
        error = anthropic.APIConnectionError(request=MagicMock())
        success = _make_mock_response()
        client._client.messages.create.side_effect = [error, success]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_on_connection_error(self, mock_sleep):
        """AnthropicClient retries on ConnectionError."""
        client = _make_client(base_retry_delay=0.01)
        success = _make_mock_response()
        client._client.messages.create.side_effect = [
            ConnectionError("conn failed"), success,
        ]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_on_timeout_error(self, mock_sleep):
        """AnthropicClient retries on TimeoutError."""
        client = _make_client(base_retry_delay=0.01)
        success = _make_mock_response()
        client._client.messages.create.side_effect = [
            TimeoutError("timed out"), success,
        ]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"

    def test_does_not_retry_on_auth_error(self):
        """AnthropicClient does NOT retry on AuthenticationError."""
        client = _make_client()
        error = anthropic.AuthenticationError(
            "bad key",
            response=_make_mock_http_response(401),
            body=None,
        )
        client._client.messages.create.side_effect = error
        with pytest.raises(anthropic.AuthenticationError):
            client.complete(system="sys", user="usr")
        assert client._client.messages.create.call_count == 1

    def test_does_not_retry_on_bad_request(self):
        """AnthropicClient does NOT retry on BadRequestError."""
        client = _make_client()
        error = anthropic.BadRequestError(
            "bad request",
            response=_make_mock_http_response(400),
            body=None,
        )
        client._client.messages.create.side_effect = error
        with pytest.raises(anthropic.BadRequestError):
            client.complete(system="sys", user="usr")
        assert client._client.messages.create.call_count == 1

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_retries_up_to_max_then_raises(self, mock_sleep):
        """AnthropicClient retries up to max_retries times then raises."""
        client = _make_client(max_retries=2, base_retry_delay=0.01)
        error = anthropic.RateLimitError(
            "rate limited",
            response=_make_mock_http_response(429),
            body=None,
        )
        client._client.messages.create.side_effect = error
        with pytest.raises(anthropic.RateLimitError):
            client.complete(system="sys", user="usr")
        # 1 initial + 2 retries = 3 total calls
        assert client._client.messages.create.call_count == 3

    @patch("ares.dialectic.agents.strategies.client.time.sleep")
    def test_succeeds_on_retry_after_transient_failure(self, mock_sleep):
        """AnthropicClient succeeds on retry after transient failure."""
        client = _make_client(max_retries=3, base_retry_delay=0.01)
        error = anthropic.InternalServerError(
            "server error",
            response=_make_mock_http_response(500),
            body=None,
        )
        success = _make_mock_response()
        # Fail twice, then succeed
        client._client.messages.create.side_effect = [error, error, success]
        result = client.complete(system="sys", user="usr")
        assert result.content == "response text"
        assert client._client.messages.create.call_count == 3
