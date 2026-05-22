# arXiv submission packet — Paper 1

**Prepared:** 2026-05-22 (Session 069, GO 2)
**Target archive:** arXiv cs.CR primary
**Post order:** 1 of 2 (Paper 1 first, Paper 2 v1.2 second)
**Posting blocker:** none. Paper 1 was never submitted to a double-blind venue.

---

## Submission form fields (paste into arxiv.org/submit)

### Title
The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate

### Authors
Daniel Gmys-Casiano

### Affiliation
Skyframe Innovations

### Author email (corresponding)
danny.casiano@gmail.com

### Subject classification
- **Primary:** cs.CR (Cryptography and Security)
- **Secondary:** cs.AI (Artificial Intelligence), cs.MA (Multi-Agent Systems)

### Abstract (paste verbatim — matches the PDF body)

> Multi-agent LLM architectures are increasingly deployed on the assumption that structured disagreement between AI agents produces more accurate analysis than any single agent reasoning alone. We test this assumption in a grounded cybersecurity domain using ARES (Adversarial Reasoning Engine System), a dialectical framework where three LLM agents with opposing analytical roles debate whether security events constitute genuine threats. All reasoning occurs within a closed-world evidence system of frozen, immutable evidence packets where hallucinations manifest as catchable schema violations rather than silent failures. Across 37 development sessions, 33 benchmark scenarios, and 2,001 tests with zero regressions, we find that single-turn LLM reasoning achieves 72-92% accuracy while multi-turn debate consistently degrades performance to 61-67%. We diagnose the failure mechanism with precision: asymmetric calibration dynamics where the threat-identifying agent (Architect) systematically retreats under pressure while the challenging agent (Skeptic) remains rigid regardless of counter-evidence. A targeted protocol fix solved the diagnosed problem but created an equivalent failure in the opposite direction, proving the issue is structural, not configurable. These findings converge independently with concurrent work from ETH Zurich on Byzantine consensus failure among LLM agents, and were further validated through adversarial review by three independent AI architectures (GPT 5.4 Pro, Gemini 3.1 Pro, Perplexity/Opus 4.6). We propose that the root cause is inherited: LLMs trained on human dialogue simulate the social behaviors of argument rather than performing genuine deliberation. The solution is architectural, not parametric — deterministic scaffolding that constrains debate to specific evidential claims while removing LLM judgment from final verdict computation. We release the ARES framework as a domain-specific testbed for studying multi-agent consensus behavior under verifiable ground truth.

### Keywords (free-form; arXiv doesn't gate on these)
multi-agent systems, LLM debate, adversarial reasoning, cybersecurity, calibration failure, consensus, closed-world evidence, dialectical AI

### Comments (optional, max ~200 chars)
11 pages. Companion framework (ARES) at https://github.com/b33fydan/ARES under GPL-3.0. Forthcoming companion preprint on the deterministic Skeptic primitive (Paper 2).

### License
arXiv supports several. Recommended: **CC BY 4.0** for the paper text (allows reuse with attribution). The ARES code framework is separately licensed GPL-3.0.

---

## File to upload

`docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf`

**Verification before upload:**
- 11 pages (canonical, per `docs/paper_1/CANONICAL.md`)
- Generated 2026-03-29 by `generate_paper.py`
- File exists and is the canonical artifact — do NOT regenerate; the script-vs-PDF drift risk is documented in `CANONICAL.md`

**arXiv submission mode:** PDF-only. arXiv prefers LaTeX source but PDF-only is accepted. Paper 1 has no LaTeX source; the PDF was generated programmatically via `generate_paper.py`. PDF-only submissions go through additional manual verification on arXiv's side (~1-2 day delay).

---

## After posting

Once arXiv assigns a paper number (e.g., `arXiv:2605.XXXXX`):

1. Update `docs/paper_1/CANONICAL.md` — set "Stable identifier" field from "(none yet — venue, DOI, arXiv ID pending)" to the actual arXiv ID + the implicit DOI `10.48550/arXiv.<ID>`.
2. Update `docs/paper_2/references.bib` — the `gmys-casiano-2026` entry (which points at Paper 1 from Paper 2's perspective) gets the new arXiv `eprint` and `doi` fields added.
3. Update `docs/paper_3/references.bib` — the `gmys-casiano-2026` entry there points at Paper 2, not Paper 1, so it stays unchanged from Paper 1's posting. But the Paper 2 posting (below) will update it.
4. Update `CLAUDE.md` "Where We Are" first line to mention the arXiv ID.
5. Land the changes in a session squash commit.

---

## Cross-references

- Paper 1 cites no other Gmys-Casiano papers (it's the first).
- Paper 2 v1.2 cites Paper 1 — once Paper 1 is on arXiv, Paper 2's references.bib should be updated BEFORE Paper 2's own arXiv submission (so Paper 2's references include the arXiv ID for Paper 1).
- Paper 3 cites Paper 2, not Paper 1 directly — no transitive update needed for Paper 3 from Paper 1's posting alone.

---

## Open questions for strategy review

1. **License choice for the paper text** — CC BY 4.0 vs CC BY-SA 4.0 vs CC0 vs arXiv-default. Dan/strategy to confirm.
2. **ORCID linkage** — if Dan has an ORCID, link at submission time. If not, arXiv will assign a paperless ID; ORCID can be added later.
3. **Comments field** — whether to mention "Paper 2 forthcoming" explicitly; mentioning it signals research-program continuity but isn't required.
