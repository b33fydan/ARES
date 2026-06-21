import dataclasses
import pytest
from ares.dialectic.evidence import Provenance, SourceType
from ares.harness.capture import CapturedRecord, capture, is_trusted


def manual_prov():
    return Provenance(source_type=SourceType.MANUAL, source_id="user")


def unknown_prov():
    return Provenance(source_type=SourceType.UNKNOWN, source_id="web:example.com")


def test_content_hash_auto_computed():
    rec = capture("r1", "hello world", manual_prov())
    assert rec.content_hash is not None
    assert len(rec.content_hash) == 16


def test_same_content_same_hash():
    a = capture("r1", "payload", manual_prov())
    b = capture("r2", "payload", unknown_prov())
    assert a.content_hash == b.content_hash


def test_record_is_frozen():
    rec = capture("r1", "x", manual_prov())
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.content = "y"


def test_manual_is_trusted():
    assert is_trusted(manual_prov()) is True
    assert capture("r1", "x", manual_prov()).trusted is True


def test_unknown_is_untrusted_failsafe():
    assert is_trusted(unknown_prov()) is False
    assert capture("r1", "x", unknown_prov()).trusted is False


def test_hash_convention_matches_ares_fact():
    import hashlib, json
    from ares.harness.capture import _hash_content
    content = "hello world"
    expected = hashlib.sha256(
        json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    assert _hash_content(content) == expected
