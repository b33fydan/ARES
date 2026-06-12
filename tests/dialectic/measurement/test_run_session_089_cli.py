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
