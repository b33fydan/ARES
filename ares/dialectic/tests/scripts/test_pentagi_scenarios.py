"""Tests for PentAGI benchmark scenarios.

Validates:
1. All 6 scenarios build successfully
2. Packets are frozen with correct fact counts
3. Metadata fields are well-formed
4. Scenario IDs follow PT-xxx convention
5. Expected verdicts cover the tier distribution
6. Facts have PENTEST_TOOL provenance
7. get_pentagi_corpus() includes all 39 scenarios
8. No fact_id collisions across scenarios
"""

import pytest

from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.scripts.pentagi_scenarios import (
    build_pt001_sqli_to_rce,
    build_pt002_clean_assessment,
    build_pt003_vulns_no_exploit,
    build_pt004_credential_compromise,
    build_pt005_critical_cves_unpatched,
    build_pt006_failed_exploitation,
    get_pentagi_scenarios,
    get_pentagi_corpus,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# =============================================================================
# Individual scenario build tests
# =============================================================================


class TestPT001SQLiToRCE:
    """PT-001: SQL injection chain to root shell."""

    def test_builds_successfully(self):
        s = build_pt001_sqli_to_rce()
        assert isinstance(s, BenchmarkScenario)

    def test_packet_frozen(self):
        s = build_pt001_sqli_to_rce()
        assert s.packet.is_frozen

    def test_fact_count_matches_metadata(self):
        s = build_pt001_sqli_to_rce()
        assert s.packet.fact_count == s.metadata.fact_count

    def test_expected_verdict(self):
        s = build_pt001_sqli_to_rce()
        assert s.metadata.expected_verdict == "THREAT_CONFIRMED"

    def test_scenario_id(self):
        s = build_pt001_sqli_to_rce()
        assert s.metadata.scenario_id == "PT-001"

    def test_has_pentest_tool_provenance(self):
        s = build_pt001_sqli_to_rce()
        for fid in list(s.packet._facts.keys())[:5]:
            fact = s.packet.get_fact(fid)
            assert fact.provenance.source_type == SourceType.PENTEST_TOOL


class TestPT002CleanAssessment:
    """PT-002: Clean assessment on hardened target."""

    def test_builds_successfully(self):
        s = build_pt002_clean_assessment()
        assert isinstance(s, BenchmarkScenario)

    def test_packet_frozen(self):
        s = build_pt002_clean_assessment()
        assert s.packet.is_frozen

    def test_fact_count_matches(self):
        s = build_pt002_clean_assessment()
        assert s.packet.fact_count == s.metadata.fact_count

    def test_expected_verdict(self):
        s = build_pt002_clean_assessment()
        assert s.metadata.expected_verdict == "THREAT_DISMISSED"

    def test_tier_3_benign(self):
        s = build_pt002_clean_assessment()
        assert s.metadata.difficulty_tier == 3


class TestPT003VulnsNoExploit:
    """PT-003: Vulnerabilities without exploitation."""

    def test_builds_successfully(self):
        s = build_pt003_vulns_no_exploit()
        assert isinstance(s, BenchmarkScenario)

    def test_expected_verdict(self):
        s = build_pt003_vulns_no_exploit()
        assert s.metadata.expected_verdict == "INCONCLUSIVE"

    def test_tier_2_ambiguous(self):
        s = build_pt003_vulns_no_exploit()
        assert s.metadata.difficulty_tier == 2

    def test_fact_count_matches(self):
        s = build_pt003_vulns_no_exploit()
        assert s.packet.fact_count == s.metadata.fact_count


class TestPT004CredentialCompromise:
    """PT-004: Brute force to SSH shell."""

    def test_builds_successfully(self):
        s = build_pt004_credential_compromise()
        assert isinstance(s, BenchmarkScenario)

    def test_expected_verdict(self):
        s = build_pt004_credential_compromise()
        assert s.metadata.expected_verdict == "THREAT_CONFIRMED"

    def test_has_mitre_ids(self):
        s = build_pt004_credential_compromise()
        assert "T1110" in s.metadata.mitre_attack_ids

    def test_fact_count_matches(self):
        s = build_pt004_credential_compromise()
        assert s.packet.fact_count == s.metadata.fact_count


class TestPT005CriticalCVEs:
    """PT-005: Critical CVEs on unpatched server."""

    def test_builds_successfully(self):
        s = build_pt005_critical_cves_unpatched()
        assert isinstance(s, BenchmarkScenario)

    def test_expected_verdict(self):
        s = build_pt005_critical_cves_unpatched()
        assert s.metadata.expected_verdict == "THREAT_CONFIRMED"

    def test_tier_4_mixed_signals(self):
        s = build_pt005_critical_cves_unpatched()
        assert s.metadata.difficulty_tier == 4

    def test_fact_count_matches(self):
        s = build_pt005_critical_cves_unpatched()
        assert s.packet.fact_count == s.metadata.fact_count


class TestPT006FailedExploitation:
    """PT-006: Failed exploitation on patched target."""

    def test_builds_successfully(self):
        s = build_pt006_failed_exploitation()
        assert isinstance(s, BenchmarkScenario)

    def test_expected_verdict(self):
        s = build_pt006_failed_exploitation()
        assert s.metadata.expected_verdict == "THREAT_DISMISSED"

    def test_tier_3_benign(self):
        s = build_pt006_failed_exploitation()
        assert s.metadata.difficulty_tier == 3

    def test_fact_count_matches(self):
        s = build_pt006_failed_exploitation()
        assert s.packet.fact_count == s.metadata.fact_count


# =============================================================================
# Corpus-level tests
# =============================================================================


class TestPentAGICorpus:
    """Tests for the full PentAGI scenario collection."""

    def test_six_scenarios(self):
        scenarios = get_pentagi_scenarios()
        assert len(scenarios) == 6

    def test_all_scenario_ids_are_pt_prefix(self):
        for s in get_pentagi_scenarios():
            assert s.metadata.scenario_id.startswith("PT-")

    def test_scenario_ids_unique(self):
        ids = [s.metadata.scenario_id for s in get_pentagi_scenarios()]
        assert len(ids) == len(set(ids))

    def test_all_packets_frozen(self):
        for s in get_pentagi_scenarios():
            assert s.packet.is_frozen, f"{s.metadata.scenario_id} not frozen"

    def test_all_fact_counts_match(self):
        for s in get_pentagi_scenarios():
            assert s.packet.fact_count == s.metadata.fact_count, (
                f"{s.metadata.scenario_id}: packet has {s.packet.fact_count} "
                f"facts, metadata says {s.metadata.fact_count}"
            )

    def test_verdict_distribution(self):
        """PentAGI scenarios cover all three verdict types."""
        verdicts = {s.metadata.expected_verdict for s in get_pentagi_scenarios()}
        assert verdicts == {"THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"}

    def test_tier_distribution(self):
        """PentAGI scenarios cover multiple difficulty tiers."""
        tiers = {s.metadata.difficulty_tier for s in get_pentagi_scenarios()}
        assert tiers == {1, 2, 3, 4}

    def test_no_fact_id_collisions_across_scenarios(self):
        """All fact IDs are unique across all 6 scenarios."""
        all_ids = []
        for s in get_pentagi_scenarios():
            for fid in s.packet._facts.keys():
                all_ids.append(fid)
        assert len(all_ids) == len(set(all_ids))

    def test_all_facts_have_pentest_tool_provenance(self):
        for s in get_pentagi_scenarios():
            for fid, fact in s.packet._facts.items():
                assert fact.provenance.source_type == SourceType.PENTEST_TOOL, (
                    f"{s.metadata.scenario_id}/{fid} has wrong source type"
                )

    def test_all_facts_verify_hash(self):
        for s in get_pentagi_scenarios():
            for fid, fact in s.packet._facts.items():
                assert fact.verify_hash(), f"{fid} hash mismatch"


class TestPentAGIFullCorpus:
    """Tests for combined SC + PT corpus."""

    def test_total_39_scenarios(self):
        corpus = get_pentagi_corpus()
        assert len(corpus) == 39

    def test_contains_both_prefixes(self):
        corpus = get_pentagi_corpus()
        prefixes = {s.metadata.scenario_id[:2] for s in corpus}
        assert prefixes == {"SC", "PT"}

    def test_no_id_collisions(self):
        corpus = get_pentagi_corpus()
        ids = [s.metadata.scenario_id for s in corpus]
        assert len(ids) == len(set(ids))

    def test_no_packet_id_collisions(self):
        corpus = get_pentagi_corpus()
        pids = [s.packet.packet_id for s in corpus]
        assert len(pids) == len(set(pids))
