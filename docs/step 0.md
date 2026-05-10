\`cat ares/dialectic/agents/oracle\_support\_set.py\`  
\`\`\`python  
"""Phase 7 Step 0 support-set Oracle.

This module leaves :mod:\`ares.dialectic.agents.oracle\` untouched. It mirrors  
the V1 Oracle decision table, but replaces the Skeptic assertion-count input  
to secondary rules with a normalized support-ref set. LLM Skeptic refs are its  
cited fact IDs; Light Skeptic refs are the facts that triggered deterministic  
rules.  
"""

from \_\_future\_\_ import annotations

from dataclasses import dataclass  
from typing import Iterable, TYPE\_CHECKING

from ares.dialectic.agents.oracle import OracleJudge  
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome

if TYPE\_CHECKING:  
    from ares.dialectic.evidence.packet import EvidencePacket  
    from ares.dialectic.messages.protocol import DialecticalMessage

PRIMARY\_CONFIRM \= "primary\_confirm"  
PRIMARY\_DISMISS \= "primary\_dismiss"  
SECONDARY\_CONFIRM \= "secondary\_confirm"  
SECONDARY\_DISMISS \= "secondary\_dismiss"  
FALLBACK\_INCONCLUSIVE \= "fallback\_inconclusive"

@dataclass(frozen=True)  
class SupportSetOracleResult:  
    """Verdict plus the support-set inputs used to reach it."""

    verdict: Verdict  
    decision\_path: str  
    architect\_fact\_ids: frozenset\[str\]  
    skeptic\_support\_refs: frozenset\[str\]

def \_valid\_refs(  
    refs: Iterable\[str\],  
    packet: "EvidencePacket",  
) \-\> frozenset\[str\]:  
    """Keep only fact IDs present in the closed-world packet."""  
    return frozenset(fid for fid in refs if packet.has\_fact(fid))

def compute\_support\_set\_verdict(  
    architect\_msg: "DialecticalMessage",  
    skeptic\_msg: "DialecticalMessage",  
    packet: "EvidencePacket",  
    \*,  
    skeptic\_support\_refs: Iterable\[str\] | None \= None,  
) \-\> SupportSetOracleResult:  
    """Compute an Oracle verdict with normalized Skeptic support refs.

    Args:  
        architect\_msg: Architect THESIS message.  
        skeptic\_msg: Skeptic ANTITHESIS message.  
        packet: Frozen evidence packet for closed-world validation.  
        skeptic\_support\_refs: Optional normalized refs. If omitted, the  
            Skeptic's cited fact IDs are used, matching LLM Skeptic behavior.

    Returns:  
        SupportSetOracleResult carrying the Verdict and decision path.  
    """  
    arch\_conf \= architect\_msg.confidence  
    skep\_conf \= skeptic\_msg.confidence  
    arch\_facts \= \_valid\_refs(architect\_msg.get\_all\_fact\_ids(), packet)  
    if skeptic\_support\_refs is None:  
        skep\_refs \= \_valid\_refs(skeptic\_msg.get\_all\_fact\_ids(), packet)  
    else:  
        skep\_refs \= \_valid\_refs(skeptic\_support\_refs, packet)

    arch\_count \= len(arch\_facts)  
    skep\_count \= len(skep\_refs)

    outcome: VerdictOutcome  
    decision\_path: str  
    reasoning: str

    if (  
        arch\_conf \>= OracleJudge.CONFIRM\_THRESHOLD  
        and skep\_conf \< OracleJudge.WEAK\_THRESHOLD  
    ):  
        outcome \= VerdictOutcome.THREAT\_CONFIRMED  
        decision\_path \= PRIMARY\_CONFIRM  
        reasoning \= (  
            f"Primary confirm: architect={arch\_conf:.2f} \>= "  
            f"{OracleJudge.CONFIRM\_THRESHOLD}, skeptic={skep\_conf:.2f} \< "  
            f"{OracleJudge.WEAK\_THRESHOLD}"  
        )  
    elif (  
        skep\_conf \>= OracleJudge.DISMISS\_THRESHOLD  
        and arch\_conf \< OracleJudge.WEAK\_THRESHOLD  
    ):  
        outcome \= VerdictOutcome.THREAT\_DISMISSED  
        decision\_path \= PRIMARY\_DISMISS  
        reasoning \= (  
            f"Primary dismiss: skeptic={skep\_conf:.2f} \>= "  
            f"{OracleJudge.DISMISS\_THRESHOLD}, architect={arch\_conf:.2f} \< "  
            f"{OracleJudge.WEAK\_THRESHOLD}"  
        )  
    elif (  
        arch\_conf \>= OracleJudge.CONFIRM\_THRESHOLD  
        and arch\_count \> skep\_count \* 2  
    ):  
        outcome \= VerdictOutcome.THREAT\_CONFIRMED  
        decision\_path \= SECONDARY\_CONFIRM  
        reasoning \= (  
            f"Secondary confirm: architect={arch\_conf:.2f}, "  
            f"arch\_refs={arch\_count} \> support\_refs={skep\_count} \* 2"  
        )  
    elif (  
        skep\_conf \>= OracleJudge.DISMISS\_THRESHOLD  
        and skep\_count \> arch\_count \* 2  
    ):  
        outcome \= VerdictOutcome.THREAT\_DISMISSED  
        decision\_path \= SECONDARY\_DISMISS  
        reasoning \= (  
            f"Secondary dismiss: skeptic={skep\_conf:.2f}, "  
            f"support\_refs={skep\_count} \> arch\_refs={arch\_count} \* 2"  
        )  
    else:  
        outcome \= VerdictOutcome.INCONCLUSIVE  
        decision\_path \= FALLBACK\_INCONCLUSIVE  
        reasoning \= (  
            f"Fallback inconclusive: architect={arch\_conf:.2f} "  
            f"({arch\_count} refs), skeptic={skep\_conf:.2f} "  
            f"({skep\_count} support refs)"  
        )

    if outcome \== VerdictOutcome.THREAT\_CONFIRMED:  
        supporting\_facts \= arch\_facts  
        final\_confidence \= arch\_conf  
    elif outcome \== VerdictOutcome.THREAT\_DISMISSED:  
        supporting\_facts \= skep\_refs  
        final\_confidence \= skep\_conf  
    else:  
        supporting\_facts \= arch\_facts | skep\_refs  
        final\_confidence \= (arch\_conf \+ skep\_conf) / 2

    verdict \= Verdict(  
        outcome=outcome,  
        confidence=final\_confidence,  
        supporting\_fact\_ids=supporting\_facts,  
        architect\_confidence=arch\_conf,  
        skeptic\_confidence=skep\_conf,  
        reasoning=reasoning,  
    )

    return SupportSetOracleResult(  
        verdict=verdict,  
        decision\_path=decision\_path,  
        architect\_fact\_ids=arch\_facts,  
        skeptic\_support\_refs=skep\_refs,  
    )  
\`\`\`

\`sed \-n '240,269p' ares/dialectic/agents/light\_skeptic.py\`  
\`\`\`python  
    \# Clamp the contributions individually to \[0, 1\] so the schema's  
    \# invariants hold even if future rules overshoot.  
    benign\_score \= \_clamp01(benign\_score)  
    malign\_score \= \_clamp01(malign\_score)  
    confidence \= \_clamp01(0.5 \+ benign\_score \- malign\_score)

    return LightSkepticJudgment(  
        confidence=confidence,  
        rationale=tuple(rationale),  
        triggered\_rules=tuple(triggered),  
        benign\_score=benign\_score,  
        malign\_score=malign\_score,  
    )

def support\_refs\_for\_judgment(  
    evidence\_packet: EvidencePacket,  
    judgment: LightSkepticJudgment,  
) \-\> frozenset\[str\]:  
    """Return fact IDs that support a Light Skeptic judgment's fired rules.

    This is intentionally separate from \`\`evaluate\`\` so existing Light Skeptic  
    confidence behavior remains unchanged. Phase 7 Step 0 uses these refs to  
    give the deterministic Skeptic symmetric access to Oracle secondary  
    evidence-count rules without fabricating assertions.  
    """  
    triggered \= set(judgment.triggered\_rules)  
    refs: set\[str\] \= set()

    for fact in evidence\_packet.get\_all\_facts():  
\`\`\`

\`git status\`  
\`\`\`text  
On branch main  
Your branch is up to date with 'origin/main'.

Changes not staged for commit:  
  (use "git add \<file\>..." to update what will be committed)  
  (use "git restore \<file\>..." to discard changes in working directory)  
	modified:   ares/dialectic/agents/light\_skeptic.py  
	modified:   ares/dialectic/tests/agents/test\_light\_skeptic.py

Untracked files:  
  (use "git add \<file\>..." to include in what will be committed)  
	"ARES Tribunal V3 \\342\\200\\224 Codex Briefing.md"  
	PHASE\_7\_STEP\_0\_PREREGISTRATION.md  
	ares/dialectic/agents/oracle\_support\_set.py  
	ares/dialectic/scripts/phase7\_step0.py  
	ares/dialectic/tests/agents/test\_oracle\_support\_set.py  
	docs/phase\_7/  
	results/phase\_7/

no changes added to commit (use "git add" and/or "git commit \-a")  
\`\`\`

\`git diff \--stat HEAD\`  
\`\`\`text  
 ares/dialectic/agents/light\_skeptic.py            | 31 \+++++++++++++++++++++++  
 ares/dialectic/tests/agents/test\_light\_skeptic.py | 31 \+++++++++++++++++++++++  
 2 files changed, 62 insertions(+)  
\`\`\`

\`sha256sum ares/dialectic/agents/oracle\_support\_set.py ares/dialectic/agents/light\_skeptic.py\`  
\`\`\`text  
0a6afd72290a40625044a6c2f33a89113f6770b6d63c30db09e012c395c67259  ares/dialectic/agents/oracle\_support\_set.py  
eac1aded1abb12533f1f00853fca8769ca01130efea560ac67537faa9645cc6f  ares/dialectic/agents/light\_skeptic.py  
\`\`\`  
