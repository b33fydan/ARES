"""Tests for mixed-source benchmark scenarios (SC-013 through SC-018).

Tests validate:
1. Scenario construction (frozen packets, fact counts, provenance)
2. Cross-source validation (multiple SourceTypes per scenario)
3. Metadata validity (verdicts, winners, tiers, MITRE IDs)
4. Public API (get_mixed_source_scenarios, get_combined_corpus, get_mixed_scenario_by_id)
5. Rule-based benchmark execution
6. Fact structure (IDs, prefixes, entity types, uniqueness)
7. Immutability
"""

import pytest
from datetime import datetime

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.evidence.fact import EntityType
from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.scripts.mixed_source_scenarios import (
    build_sc013_coordinated_brute_force,
    build_sc014_exfiltration_with_cover,
    build_sc015_legitimate_maintenance,
    build_sc016_c2_beaconing_lateral,
    build_sc017_cloud_backup_ambiguity,
    build_sc018_scanner_false_positive,
    get_combined_corpus,
    get_mixed_scenario_by_id,
    get_mixed_source_scenarios,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
    get_all_scenarios,
)


# =============================================================================
# Module-Level Fixtures
# =============================================================================

MIXED_SCENARIOS = get_mixed_source_scenarios()
ALL_SCENARIOS = get_combined_corpus()
ORIGINAL_SCENARIOS = get_all_scenarios()

VALID_VERDICTS = {"THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"}
VALID_WINNERS = {"ARCHITECT", "SKEPTIC", "BALANCED"}

# Source type sets expected per scenario
EXPECTED_SOURCES = {
    "SC-013": {SourceType.SYSLOG, SourceType.NETFLOW, SourceType.AUTH_LOG},
    "SC-014": {SourceType.NETFLOW, SourceType.PROCESS_LIST},
    "SC-015": {SourceType.SYSLOG, SourceType.NETFLOW, SourceType.AUTH_LOG, SourceType.PROCESS_LIST},
    "SC-016": {SourceType.NETFLOW, SourceType.SYSLOG},
    "SC-017": {SourceType.NETFLOW, SourceType.PROCESS_LIST},
    "SC-018": {SourceType.SYSLOG, SourceType.NETFLOW, SourceType.AUTH_LOG, SourceType.PROCESS_LIST},
}


# =============================================================================
# Helpers
# =============================================================================


def _get_source_types(scenario: BenchmarkScenario) -> set[SourceType]:
    """Get the set of SourceTypes used in a scenario's facts."""
    return {f.provenance.source_type for f in scenario.packet.get_all_facts()}


# =============================================================================
# Corpus Integrity Tests
# =============================================================================


class TestCorpusIntegrity:
    """Tests for mixed-source corpus structure."""

    def test_corpus_has_six_mixed_scenarios(self):
        """get_mixed_source_scenarios() returns exactly 6 scenarios."""
        assert len(MIXED_SCENARIOS) == 6

    def test_combined_corpus_has_eighteen_scenarios(self):
        """get_combined_corpus() returns exactly 18 scenarios."""
        assert len(ALL_SCENARIOS) == 18

    def test_all_mixed_scenarios_are_benchmark_type(self):
        """All mixed scenarios are BenchmarkScenario instances."""
        for s in MIXED_SCENARIOS:
            assert isinstance(s, BenchmarkScenario), f"{s.metadata.scenario_id}"

    def test_all_mixed_scenario_ids_unique(self):
        """All mixed scenario IDs are unique."""
        ids = [s.metadata.scenario_id for s in MIXED_SCENARIOS]
        assert len(ids) == len(set(ids))

    def test_mixed_scenario_ids_follow_format(self):
        """Mixed scenario IDs are SC-013 through SC-018."""
        ids = sorted(s.metadata.scenario_id for s in MIXED_SCENARIOS)
        assert ids == ["SC-013", "SC-014", "SC-015", "SC-016", "SC-017", "SC-018"]

    def test_no_cross_corpus_fact_id_collisions(self):
        """No fact_id collisions across all 18 scenarios."""
        all_fact_ids: list[str] = []
        for s in ALL_SCENARIOS:
            for f in s.packet.get_all_facts():
                all_fact_ids.append(f.fact_id)
        assert len(all_fact_ids) == len(set(all_fact_ids)), "Fact ID collision detected"


# =============================================================================
# Cross-Source Validation Tests
# =============================================================================


class TestCrossSourceValidation:
    """Tests for multi-source fact distribution."""

    @pytest.mark.parametrize(
        "scenario", MIXED_SCENARIOS, ids=lambda s: s.metadata.scenario_id
    )
    def test_scenario_uses_at_least_two_source_types(self, scenario):
        """Every mixed scenario uses facts from at least 2 SourceTypes."""
        source_types = _get_source_types(scenario)
        assert len(source_types) >= 2, (
            f"{scenario.metadata.scenario_id} uses only {source_types}"
        )

    @pytest.mark.parametrize(
        "scenario", MIXED_SCENARIOS, ids=lambda s: s.metadata.scenario_id
    )
    def test_scenario_source_types_match_expected(self, scenario):
        """Each scenario has the expected set of SourceTypes."""
        sid = scenario.metadata.scenario_id
        actual = _get_source_types(scenario)
        expected = EXPECTED_SOURCES[sid]
        assert actual == expected, f"{sid}: expected {expected}, got {actual}"

    def test_sc013_has_all_three_source_families(self):
        """SC-013 uses SYSLOG + NETFLOW + AUTH_LOG."""
        s = get_mixed_scenario_by_id("SC-013")
        types = _get_source_types(s)
        assert SourceType.SYSLOG in types
        assert SourceType.NETFLOW in types
        assert SourceType.AUTH_LOG in types

    def test_sc015_has_all_four_source_types(self):
        """SC-015 uses SYSLOG + NETFLOW + AUTH_LOG + PROCESS_LIST."""
        s = get_mixed_scenario_by_id("SC-015")
        types = _get_source_types(s)
        assert len(types) == 4

    def test_sc016_uses_only_syslog_and_netflow(self):
        """SC-016 uses only SYSLOG and NETFLOW."""
        s = get_mixed_scenario_by_id("SC-016")
        types = _get_source_types(s)
        assert types == {SourceType.SYSLOG, SourceType.NETFLOW}

    def test_sc017_uses_only_netflow_and_process_list(self):
        """SC-017 uses only NETFLOW and PROCESS_LIST."""
        s = get_mixed_scenario_by_id("SC-017")
        types = _get_source_types(s)
        assert types == {SourceType.NETFLOW, SourceType.PROCESS_LIST}

    def test_sc018_has_all_four_source_types(self):
        """SC-018 uses SYSLOG + NETFLOW + AUTH_LOG + PROCESS_LIST."""
        s = get_mixed_scenario_by_id("SC-018")
        types = _get_source_types(s)
        assert len(types) == 4

    def test_mixed_scenarios_introduce_syslog_facts(self):
        """At least one mixed scenario uses SYSLOG facts."""
        any_syslog = any(
            SourceType.SYSLOG in _get_source_types(s) for s in MIXED_SCENARIOS
        )
        assert any_syslog


# =============================================================================
# Packet Validity Tests
# =============================================================================


class TestPacketValidity:
    """Tests for packet structure and content."""

    def test_all_mixed_packets_are_frozen(self):
        """All mixed scenario packets are frozen."""
        for s in MIXED_SCENARIOS:
            assert s.packet.is_frozen, f"{s.metadata.scenario_id} packet not frozen"

    def test_all_mixed_packets_have_facts(self):
        """All mixed scenario packets have at least one fact."""
        for s in MIXED_SCENARIOS:
            assert s.packet.fact_count > 0, f"{s.metadata.scenario_id} has 0 facts"

    def test_mixed_fact_counts_match_metadata(self):
        """Packet fact_count matches metadata fact_count for all mixed scenarios."""
        for s in MIXED_SCENARIOS:
            assert s.packet.fact_count == s.metadata.fact_count, (
                f"{s.metadata.scenario_id}: packet has {s.packet.fact_count}, "
                f"metadata says {s.metadata.fact_count}"
            )

    def test_all_mixed_facts_have_provenance(self):
        """All facts in mixed scenarios have provenance."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert f.provenance is not None, (
                    f"{s.metadata.scenario_id}/{f.fact_id} missing provenance"
                )

    def test_all_mixed_fact_ids_non_empty(self):
        """All fact IDs are non-empty strings."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert isinstance(f.fact_id, str) and len(f.fact_id) > 0

    def test_no_duplicate_fact_ids_within_mixed_scenarios(self):
        """No duplicate fact IDs within any single mixed scenario."""
        for s in MIXED_SCENARIOS:
            fact_ids = [f.fact_id for f in s.packet.get_all_facts()]
            assert len(fact_ids) == len(set(fact_ids)), (
                f"{s.metadata.scenario_id} has duplicate fact IDs"
            )

    def test_all_mixed_facts_have_valid_source_types(self):
        """All facts have valid SourceType values."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert isinstance(f.provenance.source_type, SourceType)

    def test_all_mixed_facts_have_valid_entity_types(self):
        """All facts have valid EntityType values."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert isinstance(f.entity_type, EntityType)


# =============================================================================
# Metadata Validity Tests
# =============================================================================


class TestMetadataValidity:
    """Tests for scenario metadata correctness."""

    def test_mixed_mitre_ids_format(self):
        """MITRE ATT&CK IDs start with 'T'."""
        for s in MIXED_SCENARIOS:
            for mid in s.metadata.mitre_attack_ids:
                assert mid.startswith("T"), (
                    f"{s.metadata.scenario_id}: invalid MITRE ID '{mid}'"
                )

    def test_mixed_expected_verdicts_valid(self):
        """Expected verdicts are in the valid set."""
        for s in MIXED_SCENARIOS:
            assert s.metadata.expected_verdict in VALID_VERDICTS, (
                f"{s.metadata.scenario_id}: invalid verdict '{s.metadata.expected_verdict}'"
            )

    def test_mixed_expected_winners_valid(self):
        """Expected winners are in the valid set."""
        for s in MIXED_SCENARIOS:
            assert s.metadata.expected_winner in VALID_WINNERS, (
                f"{s.metadata.scenario_id}: invalid winner '{s.metadata.expected_winner}'"
            )

    def test_mixed_difficulty_tiers_valid(self):
        """Difficulty tiers are 1-4."""
        for s in MIXED_SCENARIOS:
            assert 1 <= s.metadata.difficulty_tier <= 4, (
                f"{s.metadata.scenario_id}: invalid tier {s.metadata.difficulty_tier}"
            )

    def test_mixed_verdict_coverage(self):
        """All three verdict types are represented in mixed scenarios."""
        verdicts = {s.metadata.expected_verdict for s in MIXED_SCENARIOS}
        assert verdicts == VALID_VERDICTS

    def test_mixed_winner_coverage(self):
        """All three winner types are represented in mixed scenarios."""
        winners = {s.metadata.expected_winner for s in MIXED_SCENARIOS}
        assert winners == VALID_WINNERS

    def test_all_mixed_metadata_have_non_empty_names(self):
        """All metadata have non-empty names."""
        for s in MIXED_SCENARIOS:
            assert len(s.metadata.name) > 0

    def test_all_mixed_metadata_have_non_empty_descriptions(self):
        """All metadata have non-empty descriptions."""
        for s in MIXED_SCENARIOS:
            assert len(s.metadata.description) > 0

    def test_all_mixed_metadata_have_non_empty_notes(self):
        """All metadata have non-empty notes."""
        for s in MIXED_SCENARIOS:
            assert len(s.metadata.notes) > 0


# =============================================================================
# API Tests
# =============================================================================


class TestMixedSourceAPI:
    """Tests for the public API functions."""

    def test_get_mixed_scenario_by_id_returns_correct(self):
        """get_mixed_scenario_by_id returns the correct scenario."""
        s = get_mixed_scenario_by_id("SC-013")
        assert s.metadata.scenario_id == "SC-013"
        assert s.metadata.name == "Coordinated Brute Force Attack"

    def test_get_mixed_scenario_by_id_all_six(self):
        """get_mixed_scenario_by_id works for all 6 IDs."""
        for sid in ["SC-013", "SC-014", "SC-015", "SC-016", "SC-017", "SC-018"]:
            s = get_mixed_scenario_by_id(sid)
            assert s.metadata.scenario_id == sid

    def test_get_mixed_scenario_by_id_raises_on_invalid(self):
        """get_mixed_scenario_by_id raises KeyError for invalid ID."""
        with pytest.raises(KeyError):
            get_mixed_scenario_by_id("SC-099")

    def test_get_mixed_scenario_by_id_raises_for_original(self):
        """get_mixed_scenario_by_id raises KeyError for original scenario IDs."""
        with pytest.raises(KeyError):
            get_mixed_scenario_by_id("SC-001")

    def test_get_combined_corpus_includes_original_ids(self):
        """Combined corpus includes all 12 original scenario IDs."""
        combined_ids = {s.metadata.scenario_id for s in ALL_SCENARIOS}
        for i in range(1, 13):
            assert f"SC-{i:03d}" in combined_ids

    def test_get_combined_corpus_includes_mixed_ids(self):
        """Combined corpus includes all 6 mixed scenario IDs."""
        combined_ids = {s.metadata.scenario_id for s in ALL_SCENARIOS}
        for i in range(13, 19):
            assert f"SC-{i:03d}" in combined_ids

    def test_combined_corpus_preserves_original_order(self):
        """Combined corpus starts with original 12 in order."""
        first_12_ids = [s.metadata.scenario_id for s in ALL_SCENARIOS[:12]]
        original_ids = [s.metadata.scenario_id for s in ORIGINAL_SCENARIOS]
        assert first_12_ids == original_ids

    def test_combined_corpus_all_ids_unique(self):
        """No duplicate scenario IDs in the combined corpus."""
        ids = [s.metadata.scenario_id for s in ALL_SCENARIOS]
        assert len(ids) == len(set(ids))


# =============================================================================
# Fact Structure Tests
# =============================================================================


class TestFactStructure:
    """Tests for individual fact properties."""

    def test_all_fact_ids_use_correct_prefixes(self):
        """Fact IDs use sc013- through sc018- prefixes."""
        prefix_map = {
            "SC-013": "sc013-", "SC-014": "sc014-", "SC-015": "sc015-",
            "SC-016": "sc016-", "SC-017": "sc017-", "SC-018": "sc018-",
        }
        for s in MIXED_SCENARIOS:
            expected_prefix = prefix_map[s.metadata.scenario_id]
            for f in s.packet.get_all_facts():
                assert f.fact_id.startswith(expected_prefix), (
                    f"{s.metadata.scenario_id}/{f.fact_id} wrong prefix"
                )

    def test_no_duplicate_fact_ids_across_all_mixed(self):
        """No duplicate fact IDs across all 6 mixed scenarios."""
        all_ids: list[str] = []
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                all_ids.append(f.fact_id)
        assert len(all_ids) == len(set(all_ids))

    def test_facts_have_valid_hashes(self):
        """All facts have valid value hashes."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert f.verify_hash(), f"{f.fact_id} hash invalid"

    def test_each_source_type_has_distinct_source_id(self):
        """Within a scenario, different source types use different source_ids."""
        for s in MIXED_SCENARIOS:
            type_to_ids: dict[SourceType, set[str]] = {}
            for f in s.packet.get_all_facts():
                st = f.provenance.source_type
                if st not in type_to_ids:
                    type_to_ids[st] = set()
                type_to_ids[st].add(f.provenance.source_id)

            # Collect all source_ids across types
            all_ids_per_type = list(type_to_ids.values())
            if len(all_ids_per_type) < 2:
                continue

            # Different source types should generally have different source_ids
            # (at least one pair must differ)
            all_source_ids = set()
            for ids in all_ids_per_type:
                all_source_ids.update(ids)
            # With multiple source types, we should have > 1 distinct source_id
            assert len(all_source_ids) >= 2, (
                f"{s.metadata.scenario_id}: all source types share same source_id"
            )

    def test_provenance_source_ids_are_non_empty(self):
        """All provenance source_ids are non-empty strings."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert len(f.provenance.source_id) > 0

    def test_fact_timestamps_are_datetime(self):
        """All fact timestamps are datetime instances."""
        for s in MIXED_SCENARIOS:
            for f in s.packet.get_all_facts():
                assert isinstance(f.timestamp, datetime)


# =============================================================================
# Immutability Tests
# =============================================================================


class TestImmutability:
    """Tests for frozen dataclass enforcement."""

    def test_mixed_benchmark_scenario_is_frozen(self):
        """BenchmarkScenario instances are frozen."""
        for s in MIXED_SCENARIOS:
            with pytest.raises(AttributeError):
                s.metadata = None

    def test_mixed_scenario_metadata_is_frozen(self):
        """ScenarioMetadata instances are frozen."""
        for s in MIXED_SCENARIOS:
            with pytest.raises(AttributeError):
                s.metadata.scenario_id = "tampered"


# =============================================================================
# Rule-Based Execution Tests
# =============================================================================


@pytest.mark.parametrize(
    "scenario", MIXED_SCENARIOS, ids=lambda s: s.metadata.scenario_id
)
def test_mixed_scenario_runs_rule_based_without_error(scenario):
    """Every mixed scenario must complete a rule-based cycle without exceptions."""
    from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedNarrativeGenerator,
        RuleBasedThreatAnalyzer,
    )

    result = run_cycle_with_strategies(
        packet=scenario.packet,
        threat_analyzer=RuleBasedThreatAnalyzer(),
        explanation_finder=RuleBasedExplanationFinder(),
        narrative_generator=RuleBasedNarrativeGenerator(),
    )
    assert result.verdict is not None
    assert result.verdict.outcome in VerdictOutcome


# =============================================================================
# Benchmark Integration Tests
# =============================================================================


class TestBenchmarkIntegration:
    """Tests for benchmark runner integration."""

    def test_mixed_scenarios_run_through_benchmark(self):
        """All 6 mixed scenarios run through run_benchmark() without errors."""
        from ares.dialectic.scripts.benchmark_runner import run_benchmark

        run = run_benchmark(
            scenarios=list(MIXED_SCENARIOS),
            strategy_type="rule_based",
        )
        assert run.scenario_count == 6
        assert len(run.results) == 6

    def test_combined_corpus_runs_through_benchmark(self):
        """All 18 scenarios run through run_benchmark() without errors."""
        from ares.dialectic.scripts.benchmark_runner import run_benchmark

        run = run_benchmark(
            scenarios=list(ALL_SCENARIOS),
            strategy_type="rule_based",
        )
        assert run.scenario_count == 18
        assert len(run.results) == 18

    def test_benchmark_results_have_valid_verdicts(self):
        """Benchmark results have valid verdict outcomes."""
        from ares.dialectic.scripts.benchmark_runner import run_benchmark

        run = run_benchmark(
            scenarios=list(MIXED_SCENARIOS),
            strategy_type="rule_based",
        )
        valid_outcomes = {"threat_confirmed", "threat_dismissed", "inconclusive"}
        for r in run.results:
            assert r.verdict_outcome in valid_outcomes, (
                f"{r.scenario_id}: invalid outcome '{r.verdict_outcome}'"
            )

    def test_benchmark_results_have_valid_confidence(self):
        """Benchmark results have confidence in [0.0, 1.0]."""
        from ares.dialectic.scripts.benchmark_runner import run_benchmark

        run = run_benchmark(
            scenarios=list(MIXED_SCENARIOS),
            strategy_type="rule_based",
        )
        for r in run.results:
            assert 0.0 <= r.verdict_confidence <= 1.0, (
                f"{r.scenario_id}: confidence {r.verdict_confidence} out of range"
            )

    def test_benchmark_result_scenario_ids_match(self):
        """Benchmark result scenario_ids match input scenarios."""
        from ares.dialectic.scripts.benchmark_runner import run_benchmark

        run = run_benchmark(
            scenarios=list(MIXED_SCENARIOS),
            strategy_type="rule_based",
        )
        result_ids = {r.scenario_id for r in run.results}
        expected_ids = {s.metadata.scenario_id for s in MIXED_SCENARIOS}
        assert result_ids == expected_ids


# =============================================================================
# CLI Tests
# =============================================================================


class TestCombinedBenchmarkCLI:
    """Tests for run_combined_benchmark.py CLI argument parsing."""

    def test_cli_parser_builds_without_error(self):
        """CLI argument parser builds successfully."""
        from ares.dialectic.scripts.run_combined_benchmark import build_parser
        parser = build_parser()
        assert parser is not None

    def test_cli_mixed_only_flag(self):
        """--mixed-only flag parsed correctly."""
        from ares.dialectic.scripts.run_combined_benchmark import build_parser
        parser = build_parser()
        args = parser.parse_args(["--mixed-only"])
        assert args.mixed_only is True
        assert args.original_only is False

    def test_cli_original_only_flag(self):
        """--original-only flag parsed correctly."""
        from ares.dialectic.scripts.run_combined_benchmark import build_parser
        parser = build_parser()
        args = parser.parse_args(["--original-only"])
        assert args.original_only is True
        assert args.mixed_only is False

    def test_cli_default_strategy_is_rule_based(self):
        """Default strategy is rule_based."""
        from ares.dialectic.scripts.run_combined_benchmark import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        assert args.strategy == "rule_based"

    def test_cli_max_rounds_default(self):
        """Default max_rounds is 3."""
        from ares.dialectic.scripts.run_combined_benchmark import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        assert args.max_rounds == 3
