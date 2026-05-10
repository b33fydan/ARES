"""Verbatim anchor test for the deterministic Skeptic kill-criterion line.

This test asserts the exact textual contents of the line in
``ares/dialectic/agents/light_skeptic.py`` that constitutes the Paper 3
architectural commitment: the deterministic Skeptic discards the
Architect output. If this line ever changes — even cosmetically — the
"Evidence Authority Isolation" claim must be re-validated.

DO NOT modify this test to make a refactor pass. If a refactor changes
the line, either:

    (a) update this test AND re-run the full leakage harness, OR
    (b) revert the refactor.

Cheap insurance on the load-bearing primitive.

Note on EXPECTED_LINE_NUMBER: at session 058 the anchor statement
``_ = architect_output`` is on line 185, with line 184 carrying its
explanatory comment. The Session 058 brief used 184; the actual
statement is 185. The substring check is the load-bearing assertion;
the line-number check is a softer drift detector that forces a
deliberate update of the EXPECTED_LINE_NUMBER constant rather than a
silent move.
"""

from __future__ import annotations

import inspect

import ares.dialectic.agents.light_skeptic as light_skeptic_module


EXPECTED_ANCHOR_LINE: str = "_ = architect_output"
EXPECTED_LINE_NUMBER: int = 185
EXPECTED_FILE_LOCATION: str = "ares/dialectic/agents/light_skeptic.py"


def test_light_skeptic_anchor_line_present_verbatim() -> None:
    """The exact string ``_ = architect_output`` must appear in
    ``light_skeptic.py``."""
    source = inspect.getsource(light_skeptic_module)
    assert EXPECTED_ANCHOR_LINE in source, (
        f"Anchor line {EXPECTED_ANCHOR_LINE!r} not found in "
        f"{EXPECTED_FILE_LOCATION}. This line is the Paper 3 "
        f"kill-criterion anchor. Refactor blocked until resolved."
    )


def test_light_skeptic_anchor_line_number_unchanged() -> None:
    """The anchor sits on the expected line number (drift detector)."""
    file_path = inspect.getfile(light_skeptic_module)
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert EXPECTED_LINE_NUMBER <= len(lines), (
        f"File too short. Expected line {EXPECTED_LINE_NUMBER}, file "
        f"has {len(lines)} lines."
    )
    actual = lines[EXPECTED_LINE_NUMBER - 1].strip()
    assert EXPECTED_ANCHOR_LINE in actual, (
        f"Line {EXPECTED_LINE_NUMBER} is {actual!r}; expected to "
        f"contain {EXPECTED_ANCHOR_LINE!r}. Update "
        f"EXPECTED_LINE_NUMBER only with an explicit Architecture "
        f"Decision Record."
    )


def test_anchor_line_is_a_statement_not_a_comment() -> None:
    """The anchor line must be the discard statement itself, not a
    comment that happens to contain the substring."""
    file_path = inspect.getfile(light_skeptic_module)
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    actual = lines[EXPECTED_LINE_NUMBER - 1].strip()
    assert not actual.startswith("#"), (
        f"Line {EXPECTED_LINE_NUMBER} is a comment ({actual!r}); the "
        f"anchor must be the executable discard statement."
    )
