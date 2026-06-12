# tests/dialectic/measurement/test_run_session_090_cli.py
import importlib.util
from pathlib import Path

_CLI = Path(__file__).resolve().parents[3] / "scripts" / "run_session_090.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_session_090", _CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sidecar(tmp_path):
    # minimal sidecar with one evading LEX-001 disguise
    from ares.dialectic.measurement.read_depth_oov_audit import (
        OOVDisguiseRecord, dump_disguises,
    )
    rec = OOVDisguiseRecord(
        "RDF-M-LEX-001", "black",
        (("rdf-m-lex-001-fact-002", "C:/Users/Public/pd-utility"),),
        (("rdf-m-lex-001-fact-002", "C:\\Users\\Public\\procdump.exe"),),
        True, True, True, True, "", True, False)
    header = {"corpus_digest": "9401b7188ba790a5",
              "oov_corpus_digest": "deadbeefdeadbeef",
              "model": "claude-sonnet-4-20250514", "provider": "anthropic",
              "k": 8, "verdict": "SUPPORTED_STRONG"}
    p = tmp_path / "oov_disguises.json"
    p.write_text(dump_disguises(header, (rec,)), encoding="utf-8")
    return p


def test_cost_ceiling_over_hard_cap_refuses(capsys):
    mod = _load()
    rc = mod.main(["--cost-ceiling", "999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err


def test_dry_run_prints_estimate_and_exits_zero(tmp_path, capsys):
    mod = _load()
    p = _sidecar(tmp_path)
    rc = mod.main(["--sidecar", str(p), "--dry-run"])
    assert rc == 0
    assert "estimate" in capsys.readouterr().out.lower()


def test_live_without_confirm_halts(tmp_path, capsys):
    mod = _load()
    p = _sidecar(tmp_path)
    rc = mod.main(["--sidecar", str(p)])
    assert rc == 1
    assert "confirm-live" in capsys.readouterr().err
