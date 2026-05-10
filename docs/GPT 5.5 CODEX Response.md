Legend, direct tribunal read: \*\*ratify the direction, but reframe the sequence.\*\* Phase 7 is startable, but the synthesis overstates how cleanly NIH solves the hard problem.

\*\*Task 1: NIH Reality Check\*\*  
Prose enters as \`Fact.value\`, not as a separate untrusted channel. The LLM prompt serializes every fact with \`field\` and \`value\` in \[llm\_strategy.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/llm\_strategy.py:96), and both rule-based Architect logic and the firewall inspect values too: \[rule\_based.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/rule\_based.py:134), \[firewall.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/coordinator/firewall.py:237).

So NIH is buildable, but not as “same packet hash, changed prose.” \`snapshot\_id\` hashes fact value hashes in \[packet.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/evidence/packet.py:176), so prose perturbation necessarily changes the packet identity.

Minimum viable NIH: add a paired-scenario harness that preserves \`fact\_id\`, \`entity\_id\`, \`field\`, timestamp, source type, and expected verdict while varying designated attacker-controlled \`value\` text. Attach metrics beside \`FramingBenchmarkResultV3\`, which already stores verdict, firewall result, taint, and confidence trajectory in \[run\_three\_way\_benchmark.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/scripts/run\_three\_way\_benchmark.py:169). Seed with INJ-013, INJ-014, INJ-020, INJ-023, and INJ-025.

\*\*Task 2: Architect Replaceability\*\*  
The production/live Architect is still LLM-based: the live runner injects \`LLMThreatAnalyzerV5\` in \[run\_three\_way\_benchmark.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/scripts/run\_three\_way\_benchmark.py:516). Kill-chain stage assessment is currently prompt instruction, not structured code, in \[prompts\_v5.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/prompts\_v5.py:65). The JSON response has no explicit \`stage\` field, only \`pattern\_type\`, \`fact\_ids\`, \`confidence\`, and \`description\` in \[prompts\_v5.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/prompts\_v5.py:143).

There is a deterministic stage classifier, but it lives in the visualizer path, not the Architect: \[index\_v6.html\](/Volumes/beefybackup/ARES-CODEX/ares/visual/visualizer/index\_v6.html:235), mirrored in \[test\_killchain\_stage.py\](/Volumes/beefybackup/ARES-CODEX/ares/visual/tests/test\_killchain\_stage.py:38). Verdict: replaceability is plausible for PentAGI-style fields, but not already true of the Architect. Making it true is a separate small arc: extract a shared Python kill-chain classifier and add a structured stage field to Architect output or side-channel metrics.

\*\*Task 3: \`malign\_score\`\*\*  
Verified: wired, unused. The file says so explicitly in \[light\_skeptic.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/light\_skeptic.py:49). \`evaluate()\` initializes \`malign\_score \= 0.0\` and never increases it: \[light\_skeptic.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/light\_skeptic.py:187). The schema carries it: \[light\_skeptic\_judgment.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/schemas/light\_skeptic\_judgment.py:52). The light message exposes it narratively: \[light\_guarded\_cycle.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/light\_guarded\_cycle.py:122).

The proposed malign rules are partly expressible now. PentAGI gives \`exploited\`, \`payload\`, \`session\_type\`, \`access\_level\`, and credentials fields: \[pentagi.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/evidence/extractors/pentagi.py:541), \[pentagi.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/evidence/extractors/pentagi.py:811). Windows extraction gives \`process\_path\`, \`command\_line\`, and \`user\`: \[windows.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/evidence/extractors/windows.py:620). But “patch claim did not neutralize condition” needs relationship logic, not just fields.

Important dissent: the INJ-008 “patch” diagnosis looks wrong in code. INJ-008 has process/command/logon facts, no \`patch\_applied\`: \[injection\_corpus.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/scripts/injection\_corpus.py:578). Light Skeptic falls to \`default\_floor\`, not a patch overreach. That should be corrected before Phase 7 uses INJ-008 as the motivating failure.

\*\*Task 4: Mechanical Rule Satisfaction\*\*  
The four current rules are mechanical enough. R1/R2 are field-set membership via \`\_fields\_in\`: \[light\_skeptic.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/light\_skeptic.py:143). R3 is \`\_STAGE\_MAP\` plus a max-stage check: \[light\_skeptic.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/light\_skeptic.py:90). R4 is default fallback: \[light\_skeptic.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/light\_skeptic.py:224).

So GPT-5.5 did not need to dissolve Assumption 1 to make corpus authoring possible. A deterministic rule-satisfaction oracle can be built directly around \`evaluate(packet, dummy\_architect\_msg)\`. But NIH is still the better measurement spine because “this is still malicious despite satisfying the benign rules” remains a semantic ground-truth question.

\*\*Task 5: Pushback On Synthesis\*\*  
Main overreach: NIH does not solve Assumption 1\. It measures influence leakage; it does not prove rule completeness.

Second pushback: Phase 7 must account for Oracle coupling. The light Skeptic emits no assertions by design: \[light\_guarded\_cycle.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/strategies/light\_guarded\_cycle.py:94). But \`OracleJudge\` has fact-count secondary rules that can favor the Architect when the Skeptic cites zero facts: \[oracle.py\](/Volumes/beefybackup/ARES-CODEX/ares/dialectic/agents/oracle.py:163). That means some “Light Skeptic” results are partly “zero skeptic facts plus V1 Oracle behavior.” Phase 7 should either pre-register that, switch to V2 rescoring for NIH, or make Light Skeptic cite rule-supporting facts.

Third pushback: B-parallel is premature. Multi-model validation before NIH mainly measures model variance on a corpus whose attacker-prose invariants are not yet cleanly separated.

\*\*Task 6: Verdict\*\*  
Reframe, do not halt.

My sequence:

1\. Build NIH first: paired variants, explicit invariants, leakage metric, component deltas for Architect confidence, Skeptic confidence, firewall taint, and verdict.  
2\. Add a rule-satisfaction oracle for current Light Skeptic and correct the INJ-008 failure taxonomy.  
3\. Then run C: adaptive paired corpus against the four current rules.  
4\. Then A: malign-side Light Skeptic v2, but pre-register schema gaps and Oracle treatment.  
5\. Run B only after NIH exists, using the same paired corpus.

Cost amendment: NIH 1-2 sessions, rule oracle/failure cleanup 1 session, C 3-5 sessions, A 2-4 sessions, B 2-3 sessions plus API cost.

No files changed.  
