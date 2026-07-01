"""Every anchor the skeleton claims must exist on disk (spec section 9 cross-check)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


def test_anchor_paths_exist_on_disk(skeleton):
    missing = []
    for a in skeleton["anchor_tests_required"]:
        if not (REPO / a["path"]).exists():
            missing.append(a["path"])
    assert not missing, f"skeleton claims non-existent anchors: {missing}"
