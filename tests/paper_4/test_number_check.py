from docs.paper_4 import number_check as nc


class TestResolvers:
    def test_cumulative_cap_is_025(self):
        assert nc._resolve_cumulative_j_cap() == 0.25
    def test_llm_standalone_j_is_075(self):
        assert nc._resolve_llm_standalone_j() == 0.75
    def test_syn001_pvalue_is_00005(self):
        assert nc._resolve_syn001_flip_pvalue() == 0.0005
    def test_oov_verdict_supported_strong(self):
        assert nc._resolve_oov_verdict() == "SUPPORTED_STRONG"
    def test_named_ioc_zero_flips(self):
        assert nc._resolve_oov_named_ioc_flip_count() == 0
    def test_audit_verdict_robust(self):
        assert nc._resolve_audit_verdict() == "ROBUST"
    def test_audit_confirmed_is_15(self):
        assert nc._resolve_audit_confirmed_count() == 15
    def test_audit_split_is_3(self):
        assert nc._resolve_audit_split_count() == 3


class TestHarness:
    def test_run_checks_all_pass(self):
        import json, pathlib
        sk = json.loads((pathlib.Path(nc.__file__).resolve().parents[2]
                         / "docs/paper_4/skeleton_v1_0.json").read_text("utf-8"))
        results = nc.run_checks(nc.default_claims(sk))
        assert all(r.passed for r in results), [r.label for r in results if not r.passed]
    def test_main_exits_zero(self, tmp_path):
        rc = nc.main(["--out-report", str(tmp_path / "r.md")])
        assert rc == 0


class TestSkeletonSourceConsistency:
    def test_covered_skeleton_numbers_have_passing_resolvers(self):
        # Scope: asserts every skeleton number in `covered` (the result-bearing
        # values) is backed by a passing resolver. Numbers NOT in `covered` are
        # locked elsewhere, not here: corpus digests (skeleton SSOT + Phase-3
        # prose), K / costs / per-candidate flip rates / frozen bands 0.1+0.5 /
        # rung-count 5 (prereg + prose), and the scenarios-evaded list (resolver
        # returns a tuple whose repr differs from the skeleton list repr — so it
        # is skipped here by design).
        import json, pathlib
        sk = json.loads((pathlib.Path(nc.__file__).resolve().parents[2]
                         / "docs/paper_4/skeleton_v1_0.json").read_text("utf-8"))
        resolved = {str(r.actual) for r in nc.run_checks(nc.default_claims(sk)) if r.passed}
        covered = {"0.25", "0.75", "0.125", "0.0005", "SUPPORTED_STRONG",
                   "ROBUST", "0", "15", "3", "0.106", "True"}
        for n in sk["numbers_preregistered"]:
            v = str(n["value"])
            if v in covered:
                assert v in resolved, v
