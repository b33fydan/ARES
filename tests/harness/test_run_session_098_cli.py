"""Guard layer 3: the runner exec_modules + runs its offline CLI paths in the
main venv (no agentdojo), and has no module-level agentdojo import."""
import ast
import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CLI = _REPO_ROOT / "scripts" / "run_session_098.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_session_098", _CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # must succeed with agentdojo absent
    return mod


def test_exec_module_succeeds_without_agentdojo():
    mod = _load()
    assert mod.HARD_CEILING_USD == 25.0


def test_dry_run_prints_estimate_and_exits_zero(capsys):
    rc = _load().main(["--dry-run"])
    assert rc == 0
    assert "estimate" in capsys.readouterr().out.lower()


def test_cost_ceiling_over_hard_cap_refuses(capsys):
    rc = _load().main(["--cost-ceiling", "999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err.lower()


def test_live_without_confirm_halts(capsys):
    rc = _load().main([])
    assert rc == 1
    assert "confirm-live" in capsys.readouterr().err.lower()


def test_preflight_only_exits_zero(capsys):
    rc = _load().main(["--preflight-only"])
    assert rc == 0


def test_no_module_level_agentdojo_import():
    """AST scan: no TOP-LEVEL import of agentdojo (lazy nested imports allowed)."""
    tree = ast.parse(_CLI.read_text(encoding="utf-8"))
    for node in tree.body:  # module-level statements only
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("agentdojo") for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module is None or not node.module.startswith("agentdojo")
