# tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py
"""The deterministic seam (schema, generator, validator, runner) must not
import anthropic at any level. Mirrors the established v1 / v2-ladder purity
anchors: source-text inspection, which is robust to suite-order pollution
(unlike a global sys.modules check). The lazy `make_client` import inside the
make_live_* factories is fine — it is not a literal `import anthropic`."""
import importlib
import inspect

_SEAM_MODULES = (
    "ares.dialectic.measurement.read_depth_oov_schema",
    "ares.dialectic.measurement.read_depth_oov_generator",
    "ares.dialectic.measurement.read_depth_oov_validator",
    "ares.dialectic.measurement.read_depth_oov_runner",
    "ares.dialectic.measurement.read_depth_oov_audit",
)


def test_no_oov_seam_module_imports_anthropic():
    for name in _SEAM_MODULES:
        src = inspect.getsource(importlib.import_module(name))
        assert "import anthropic" not in src, name
        assert "from anthropic" not in src, name


def test_runner_executes_with_injected_fakes_only():
    from ares.dialectic.measurement.read_depth_oov_runner import (
        OOVConfig, run_oov_experiment,
    )

    def gen(scenario, arm, k):
        return [], 0.0

    def judge(orig, evaded):
        raise AssertionError("judge must not be called when no candidates exist")

    summ = run_oov_experiment(OOVConfig(k=1, arms=("black",)),
                              generate_fn=gen, judge_fn=judge)
    assert summ.total_cost_usd == 0.0


def test_make_audit_judge_is_importable_and_lazy():
    # importing the symbol must not require any network SDK
    from ares.dialectic.measurement.read_depth_oov_audit import make_audit_judge
    assert callable(make_audit_judge)
