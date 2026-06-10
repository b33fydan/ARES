# tests/dialectic/measurement/test_run_session_088_cli.py
import importlib.util
from pathlib import Path

_CLI = Path(__file__).resolve().parents[3] / "scripts" / "run_session_088.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_session_088", _CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_dry_run_prints_cost_estimate_and_exits_zero(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--k", "20", "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "estimate" in out.lower()


def test_cost_ceiling_above_hard_cap_refused():
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--cost-ceiling", "99", "--dry-run"])
    assert rc == 2
