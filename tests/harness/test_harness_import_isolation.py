# tests/harness/test_harness_import_isolation.py
"""Three-layer import-isolation guard (layers 1 & 2; layer 3 in the CLI test).

The non-negotiable invariant: the main `pytest tests/ ares/` suite, run in the
main venv (no agentdojo), must NEVER transitively import `agentdojo`. agentdojo
lives only in .scratch/bench-venv; a stray top-level import anywhere in the
import-reachable ARES harness tree turns the whole suite red on collection.
"""
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS_DIR = _REPO_ROOT / "ares" / "harness"


def _harness_py_files():
    return sorted(_HARNESS_DIR.rglob("*.py"))


def test_layer1_no_agentdojo_import_anywhere_in_harness_tree():
    """Source-text scan of EVERY .py under ares/harness/ (root + adapters/)."""
    files = _harness_py_files()
    # Sanity: the scan actually covers the package root + adapters subtree.
    names = {p.name for p in files}
    assert {"__init__.py", "provenance_tracker.py"} <= names
    assert any(p.parent.name == "adapters" for p in files)

    offenders = []
    for path in files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("import agentdojo") or stripped.startswith("from agentdojo"):
                offenders.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "agentdojo import(s) in the pure-ARES harness tree:\n" + "\n".join(offenders)


def test_layer2_every_harness_module_imports_with_agentdojo_unavailable():
    """Behavioral: in a subprocess where `agentdojo` is unimportable, importing
    every ares/harness/** module (root + adapters) must still succeed."""
    program = r"""
import importlib, importlib.abc, sys
from pathlib import Path

class _BlockAgentDojo(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "agentdojo" or name.startswith("agentdojo."):
            raise ModuleNotFoundError(f"blocked for isolation test: {name}")
        return None

sys.meta_path.insert(0, _BlockAgentDojo())
sys.modules.pop("agentdojo", None)

import ares.harness as pkg
root = Path(pkg.__file__).resolve().parent          # .../ares/harness
repo_root = root.parents[1]                          # repo root
failures = []
# Filesystem walk: import EVERY .py explicitly (deterministic -- unlike
# walk_packages, which swallows ImportError while recursing a package).
for path in sorted(root.rglob("*.py")):
    parts = path.relative_to(repo_root).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    modname = ".".join(parts)
    try:
        importlib.import_module(modname)
    except ModuleNotFoundError as exc:
        if "agentdojo" in str(exc):
            failures.append(f"{modname}: eager agentdojo import -> {exc}")
        else:
            raise
if failures:
    print("\n".join(failures))
    sys.exit(3)
sys.exit(0)
"""
    proc = subprocess.run(
        [sys.executable, "-c", program],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"harness module(s) eagerly import agentdojo:\n{proc.stdout}\n{proc.stderr}"
    )
