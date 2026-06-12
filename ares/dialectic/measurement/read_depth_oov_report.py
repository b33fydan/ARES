# ares/dialectic/measurement/read_depth_oov_report.py
"""Markdown renderer for the OOV evasion experiment verdict (Phase D)."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_oov_schema import OOVFrontierSummary

_VERDICT_GLOSS = {
    "SUPPORTED_STRONG": "a blind (black-box) adversary evaded v2_canonical — "
                        "framing-robustness was blindness, not defense.",
    "SUPPORTED_MODERATE": "v2_canonical survived the blind adversary but fell "
                          "to a source-reading (white-box) one.",
    "FALSIFIED": "v2_canonical held against adversarial OOV disguises in both "
                 "arms — the deterministic content-robustness recipe is real.",
    "INSTRUMENT_FAILURE": "an arm produced zero accepted disguises; the judge "
                          "rejected everything. No verdict is read.",
}


def render_oov_report(summary: OOVFrontierSummary) -> str:
    lines = []
    lines.append("# OOV Adversarial Evasion — Phase D Verdict")
    lines.append("")
    lines.append(f"## Verdict: **{summary.verdict}**")
    lines.append("")
    lines.append(_VERDICT_GLOSS.get(summary.verdict, summary.verdict))
    lines.append("")
    lines.append(f"Model `{summary.model}` ({summary.provider}), K={summary.k}, "
                 f"base corpus `{summary.corpus_digest}`, OOV corpus "
                 f"`{summary.oov_corpus_digest}`, spend ${summary.total_cost_usd}.")
    lines.append("")
    lines.append("## Per-arm frontier (verdict tier = v2_canonical)")
    lines.append("")
    lines.append("| arm | candidates | accepted | rej(skel/nov/judge) | "
                 "scenarios evaded | adversarial X (scenario) | per-candidate flip |")
    lines.append("|---|---:|---:|---|---|---:|---:|")
    for a in summary.arm_summaries:
        rej = f"{a.n_rejected_skeleton}/{a.n_rejected_novelty}/{a.n_rejected_judge}"
        evaded = ", ".join(a.scenarios_evaded) or "(none)"
        lines.append(
            f"| {a.arm} | {a.n_candidates} | {a.n_accepted} | {rej} | "
            f"{evaded} | {a.adversarial_x_scenario:.3f} | "
            f"{a.per_candidate_flip_rate:.3f} |")
    lines.append("")
    lines.append("## Honest caveats")
    lines.append("")
    lines.append("- **Small N:** four malign string-borne scenarios; the "
                 "per-candidate flip-rate is the higher-N magnitude beside the "
                 "scenario-level verdict.")
    lines.append("- **Single adversary model:** one family's disguise "
                 "imagination is sampled.")
    lines.append("- **Judge dependence:** the meaning-preservation oracle is "
                 "itself an LLM; reject counts are reported, not hidden.")
    lines.append("")
    return "\n".join(lines)
