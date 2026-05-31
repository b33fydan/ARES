import importlib.util
import sys
from pathlib import Path

_CLI = Path(__file__).resolve().parents[3] / "scripts" / "run_session_077.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_session_077", _CLI)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_session_077"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_cost_ceiling_above_hard_cap_refused():
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--preflight-only", "--cost-ceiling", "99"])
    assert rc == 2


def test_dry_run_makes_no_calls(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--dry-run"])
    assert rc == 0
    assert "dry run" in capsys.readouterr().out.lower()
