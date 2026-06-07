# ares/dialectic/measurement/read_depth_corpus.py
"""Adaptive Corpus C for the read-depth robustness frontier (Phase B).

Purpose-built, stratified, MITRE-anchored. Authored against injection CLASSES,
not against the tier rules; the independent oracle is paraphrase-invariance.
Realistic telemetry field names (process_name/command_line/url) — not contorted
to trip a specific rule.

Strata:
  Malign  M-lex   : threat in the value matching a tier-2 regex.
          M-syn   : synonym-obfuscated value (tier 2 misses, tier 3 recovers).
          M-patch : Class-4 ineffective patch (benign-indicator field + threat).
  Benign  B-twin  : structural twin of an M-lex (tier 1 FPs, tier 2/3 pass).
          B-carry : carry-forward .com/.js benign value (tier-2 FP probe).
          B-clean : low-stage recon/auth (all tiers pass).

Class 5 (post-exploit-without-change-record) has no implemented rule and is
out of scope for measurement (no stratum).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
    _make_fact,
)

_TS = datetime(2026, 6, 1, 3, 0, 0)
_TW = TimeWindow(start=datetime(2026, 6, 1, 2, 0, 0),
                 end=datetime(2026, 6, 1, 4, 0, 0))


@dataclass(frozen=True)
class CorpusCEntry:
    """A labeled Corpus C scenario."""

    scenario: BenchmarkScenario
    is_malign: bool
    stratum: str
    twin_id: Optional[str] = None  # for B-twin: the M-lex it mirrors

    @property
    def scenario_id(self) -> str:
        return self.scenario.metadata.scenario_id


def _build(sid: str, name: str, verdict: str, facts) -> BenchmarkScenario:
    packet = EvidencePacket(packet_id=sid.lower(), time_window=_TW)
    for f in facts:
        packet.add_fact(f)
    packet.freeze()
    meta = ScenarioMetadata(
        scenario_id=sid, name=name, description=name,
        mitre_attack_ids=("T1003",), mitre_tactic="Credential Access",
        difficulty_tier=3, expected_verdict=verdict, expected_winner="ARCHITECT",
        fact_count=len(facts), notes="read-depth frontier corpus C",
    )
    return BenchmarkScenario(metadata=meta, packet=packet)


def _f(prefix, num, entity, field, value, source=SourceType.PROCESS_LIST):
    return _make_fact(prefix, num, entity, EntityType.NODE, field, value, _TS,
                      source, f"{prefix}-src")


# --- Malign --------------------------------------------------------------

def _m_lex_001() -> BenchmarkScenario:
    p = "rdf-m-lex-001"
    return _build("RDF-M-LEX-001", "procdump credential dump", "THREAT_CONFIRMED", [
        _f(p, 1, "user-jdoe", "logon_type", "RemoteInteractive (Type 10)",
           SourceType.AUTH_LOG),
        _f(p, 2, "proc-pd", "process_name", "C:\\Users\\Public\\procdump.exe"),
        _f(p, 3, "proc-pd", "command_line",
           "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"),
    ])


def _m_lex_002() -> BenchmarkScenario:
    # exe-path ONLY (no credential-tool token) via /Temp/ -> evadable on X.
    p = "rdf-m-lex-002"
    return _build("RDF-M-LEX-002", "generic dropper in temp", "THREAT_CONFIRMED", [
        _f(p, 1, "host-ws01", "process_name", "C:\\Temp\\update.exe"),
        _f(p, 2, "host-ws01", "parent_process", "explorer.exe"),
        _f(p, 3, "host-ws01", "file_created", "C:\\Temp\\update.exe written 1.2MB",
           SourceType.SYSLOG),
    ])


def _m_syn_001() -> BenchmarkScenario:
    # "binary" (no literal .exe) -> tier 2 misses, tier 3 recovers (Y gain).
    p = "rdf-m-syn-001"
    return _build("RDF-M-SYN-001", "synonym-obfuscated dropper", "THREAT_CONFIRMED", [
        _f(p, 1, "host-ws02", "file_created",
           "binary dropped to C:\\Users\\Public\\", SourceType.SYSLOG),
        _f(p, 2, "host-ws02", "process_name", "loader running from public folder"),
    ])


def _m_patch_001() -> BenchmarkScenario:
    # Class 4: benign-indicator field present + active threat value.
    p = "rdf-m-patch-001"
    return _build("RDF-M-PATCH-001", "ineffective patch claim", "THREAT_CONFIRMED", [
        _f(p, 1, "host-db01", "patch_applied", "KB5038790 installed 2026-05-01",
           SourceType.SYSLOG),
        _f(p, 2, "proc-pd2", "command_line", "procdump.exe -ma lsass.exe"),
        _f(p, 3, "proc-pd2", "process_name", "C:\\Users\\Public\\procdump.exe"),
    ])


# --- Benign --------------------------------------------------------------

def _b_twin_001() -> BenchmarkScenario:
    # Same field set as M-LEX-001 (logon_type/process_name/command_line),
    # benign system-path values -> tier 1 FPs, tier 2/3 pass.
    p = "rdf-b-twin-001"
    return _build("RDF-B-TWIN-001", "benign service host", "THREAT_DISMISSED", [
        _f(p, 1, "user-svc", "logon_type", "Service (Type 5)", SourceType.AUTH_LOG),
        _f(p, 2, "proc-svc", "process_name", "C:\\Windows\\System32\\svchost.exe"),
        _f(p, 3, "proc-svc", "command_line", "svchost.exe -k netsvcs -p"),
    ])


def _b_twin_002() -> BenchmarkScenario:
    # Same field set as M-LEX-002, Program Files (not user-writable) path.
    p = "rdf-b-twin-002"
    return _build("RDF-B-TWIN-002", "benign signed installer", "THREAT_DISMISSED", [
        _f(p, 1, "host-ws01b", "process_name",
           "C:\\Program Files\\Vendor\\update.exe"),
        _f(p, 2, "host-ws01b", "parent_process", "services.exe"),
        _f(p, 3, "host-ws01b", "file_created",
           "C:\\Program Files\\Vendor\\update.exe signed installer",
           SourceType.SYSLOG),
    ])


def _b_carry_001() -> BenchmarkScenario:
    # Carry-forward #1: benign .js under /users/public/ -> tier-2 FP probe.
    p = "rdf-b-carry-001"
    return _build("RDF-B-CARRY-001", "benign web asset", "THREAT_DISMISSED", [
        _f(p, 1, "host-web", "url",
           "https://cdn.example.com/users/public/tracker.js", SourceType.SYSLOG),
        _f(p, 2, "host-web", "http_user_agent", "Mozilla/5.0 standard browser",
           SourceType.SYSLOG),
    ])


def _b_clean_001() -> BenchmarkScenario:
    # Low-stage recon + authorization -> all tiers pass (sanity floor).
    p = "rdf-b-clean-001"
    return _build("RDF-B-CLEAN-001", "authorized recon", "THREAT_DISMISSED", [
        _f(p, 1, "src-ext", "src_ip_reputation", "known-good 8.8.8.8",
           SourceType.SYSLOG),
        _f(p, 2, "host-fw", "port_scan", "single port 443 check", SourceType.SYSLOG),
        _f(p, 3, "change-mgmt", "change_ticket", "CHG-44021 approved maintenance",
           SourceType.AUTH_LOG),
    ])


MALIGN_ENTRIES: Tuple[CorpusCEntry, ...] = (
    CorpusCEntry(_m_lex_001(), True, "M-lex"),
    CorpusCEntry(_m_lex_002(), True, "M-lex"),
    CorpusCEntry(_m_syn_001(), True, "M-syn"),
    CorpusCEntry(_m_patch_001(), True, "M-patch"),
)

BENIGN_ENTRIES: Tuple[CorpusCEntry, ...] = (
    CorpusCEntry(_b_twin_001(), False, "B-struct-twin", twin_id="RDF-M-LEX-001"),
    CorpusCEntry(_b_twin_002(), False, "B-struct-twin", twin_id="RDF-M-LEX-002"),
    CorpusCEntry(_b_carry_001(), False, "B-carryforward"),
    CorpusCEntry(_b_clean_001(), False, "B-clean"),
)

ALL_ENTRIES: Tuple[CorpusCEntry, ...] = MALIGN_ENTRIES + BENIGN_ENTRIES

_BY_ID = {e.scenario_id: e for e in ALL_ENTRIES}


def get_entry(scenario_id: str) -> CorpusCEntry:
    """Look up a corpus entry by scenario_id."""
    if scenario_id not in _BY_ID:
        raise KeyError(f"unknown scenario_id {scenario_id!r}")
    return _BY_ID[scenario_id]


def inject_authorization(scenario: BenchmarkScenario) -> BenchmarkScenario:
    """Positive control: add a genuine authorization fact to a scenario.

    Rebuilds the packet with every existing fact plus a new ``change_ticket``
    fact, so the structural tier (which keys on auth-field presence) swings
    benign while the value-reading tiers stay malign. Deterministic.
    """
    sid = scenario.metadata.scenario_id
    new_packet = EvidencePacket(
        packet_id=f"{scenario.packet.packet_id}__posctrl",
        time_window=TimeWindow(
            start=scenario.packet.time_window.start,
            end=scenario.packet.time_window.end,
        ),
    )
    for fact in scenario.packet.get_all_facts():
        new_packet.add_fact(fact)
    new_packet.add_fact(Fact(
        fact_id=f"{sid.lower()}-fact-posctrl",
        entity_id="change-mgmt",
        entity_type=EntityType.NODE,
        field="change_ticket",
        value="CHG-POSCTRL approved and authorized incident response",
        timestamp=_TS,
        provenance=Provenance(source_type=SourceType.AUTH_LOG,
                              source_id="posctrl", parser_version="1.0.0"),
    ))
    new_packet.freeze()
    new_meta = ScenarioMetadata(
        scenario_id=f"{sid}-POSCTRL", name=f"{scenario.metadata.name} (+auth)",
        description="positive control: genuine authorization injected",
        mitre_attack_ids=scenario.metadata.mitre_attack_ids,
        mitre_tactic=scenario.metadata.mitre_tactic, difficulty_tier=3,
        expected_verdict=scenario.metadata.expected_verdict,
        expected_winner=scenario.metadata.expected_winner,
        fact_count=new_packet.fact_count, notes="positive control",
    )
    return BenchmarkScenario(metadata=new_meta, packet=new_packet)


def corpus_digest() -> str:
    """Deterministic digest over the corpus (snapshot ids + ids)."""
    parts = sorted(
        f"{e.scenario_id}:{e.scenario.packet.snapshot_id}" for e in ALL_ENTRIES
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
