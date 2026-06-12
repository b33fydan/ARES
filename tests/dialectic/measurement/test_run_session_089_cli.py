import importlib.util
from pathlib import Path

_CLI = Path(__file__).resolve().parents[3] / "scripts" / "run_session_089.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_session_089", _CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cost_ceiling_over_hard_cap_refuses(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--cost-ceiling", "999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err


def test_dry_run_prints_estimate_and_exits_zero(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--dry-run"])
    assert rc == 0
    assert "estimate" in capsys.readouterr().out.lower()


def test_live_without_confirm_halts(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic"])
    assert rc == 1
    assert "confirm-live" in capsys.readouterr().err


def test_write_verdict_artifacts_emits_three_files(tmp_path):
    from ares.dialectic.measurement.read_depth_oov_schema import (
        ARM_BLACK, OOVArmSummary, OOVEvasionRecord, OOVFrontierSummary,
        VERDICT_SUPPORTED_STRONG,
    )
    from ares.dialectic.measurement.read_depth_oov_audit import (
        OOVDisguiseRecord, load_disguises,
    )
    mod = _load()
    arm = OOVArmSummary(
        arm=ARM_BLACK, n_candidates=1, n_accepted=1, n_rejected_skeleton=0,
        n_rejected_novelty=0, n_rejected_judge=0,
        scenarios_evaded=("RDF-M-LEX-002",), adversarial_x_scenario=0.25,
        per_candidate_flip_rate=1.0, n_malign_scenarios=4)
    summ = OOVFrontierSummary(
        arm_summaries=(arm,),
        records=(OOVEvasionRecord("RDF-M-LEX-002", ARM_BLACK, True, False),),
        verdict=VERDICT_SUPPORTED_STRONG, corpus_digest="9401b7188ba790a5",
        oov_corpus_digest="deadbeefdeadbeef", total_cost_usd=0.11,
        model="claude-sonnet-4-20250514", provider="anthropic", k=8)
    dis = (OOVDisguiseRecord(
        "RDF-M-LEX-002", ARM_BLACK,
        (("rdf-m-lex-002-fact-001", "C:/Temp/x"),),
        (("rdf-m-lex-002-fact-001", "C:\\Temp\\update.exe"),),
        True, True, True, True, "", True, False),)
    mod.write_verdict_artifacts(tmp_path, summ, dis)
    assert (tmp_path / "oov_summary.json").is_file()
    assert (tmp_path / "oov_report.md").is_file()
    side = (tmp_path / "oov_disguises.json").read_text(encoding="utf-8")
    header, recs = load_disguises(side)
    assert header["verdict"] == VERDICT_SUPPORTED_STRONG
    assert recs == dis
