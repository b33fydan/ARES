"""Root conftest.py — pytest configuration for ARES project.

Registers the --run-live-llm option and live_llm marker for tests
that make real Anthropic API calls.
"""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-live-llm",
        action="store_true",
        default=False,
        help="Run tests that make live LLM API calls (requires ANTHROPIC_API_KEY)",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_llm: marks tests that require live LLM API calls "
        "(deselect with '-m \"not live_llm\"')",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-live-llm"):
        skip_live = pytest.mark.skip(reason="Need --run-live-llm option to run")
        for item in items:
            if "live_llm" in item.keywords:
                item.add_marker(skip_live)
