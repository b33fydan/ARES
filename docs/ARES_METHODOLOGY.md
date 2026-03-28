## Methodology: The ARES Framework

In this section, we present the architecture of ARES (Adversarial Reasoning Engine System), a dialectical agentic framework for automated cybersecurity threat assessment. As illustrated in Figure \ref{fig:methodology_diagram}, ARES orchestrates a collaborative team of four specialized agents—Architect, Skeptic, Oracle Judge, and Oracle Narrator—to transform raw security telemetry into calibrated, evidence-grounded threat verdicts within a closed-world evidence architecture. (See Appendix \ref{app_sec:agent_prompts} for prompts)

### Evidence Packet (Closed-World Foundation)

Given a set of raw security observations from heterogeneous sources (syslog, netflow, auth logs, process lists, DNS logs), the Evidence Packet $\mathcal{P}$ constructs a frozen, immutable container of $K$ atomic facts $\mathcal{F} = \{f_k\}_{k=1}^{K}$, each with cryptographic provenance:
$$
\mathcal{P} = \text{Freeze}\left(\{f_k\}_{k=1}^{K}\right), \quad h(\mathcal{P}) = \text{SHA256}\left(\bigoplus_{k=1}^{K} f_k\right)
$$
where each fact $f_k \in \mathcal{F}$ is a quintuple $(e_k, \tau_k, \phi_k, v_k, \rho_k)$ representing entity, entity type, field, value, and provenance respectively. The snapshot hash $h(\mathcal{P})$ enforces the closed-world assumption: no fact may be added, modified, or removed after freezing. All downstream reasoning is grounded exclusively in $\mathcal{F}$—any claim referencing evidence outside $\mathcal{P}$ is, by definition, a hallucination and is rejected at the schema level.

### Architect Agent (Thesis Phase)

The Architect Agent serves as the threat hypothesis generator. Given the frozen evidence packet $\mathcal{P}$, it identifies anomaly patterns $\mathcal{A} = \{a_j\}_{j=1}^{J}$ aligned to the MITRE ATT\&CK taxonomy and produces a set of grounded assertions $\mathcal{Q}^{+}$ supporting the threat hypothesis:
$$
\mathcal{Q}^{+} = \text{Agent}_{\text{arch}}\left(\mathcal{P}\right), \quad \forall q \in \mathcal{Q}^{+}: \text{facts}(q) \subseteq \mathcal{F}
$$
Each assertion $q_j \in \mathcal{Q}^{+}$ is a frozen triple $(\alpha_j, \mathcal{F}_j, \gamma_j)$ where $\alpha_j$ is the assertion type (ASSERT, LINK, or ALT), $\mathcal{F}_j \subseteq \mathcal{F}$ is the set of cited facts, and $\gamma_j \in [0,1]$ is the grounded confidence. The Architect accepts a pluggable strategy $\sigma_{\text{arch}} \in \{\text{RuleBased}, \text{LLM}_{v2}\}$, enabling deterministic rule-based analysis or LLM-powered reasoning over the same evidence contract.

### Skeptic Agent (Antithesis Phase)

The Skeptic Agent challenges the Architect's threat hypothesis by constructing benign explanations $\mathcal{B} = \{b_m\}_{m=1}^{M}$ from the same evidence. It receives both $\mathcal{P}$ and the Architect's message $\mathcal{Q}^{+}$:
$$
\mathcal{Q}^{-} = \text{Agent}_{\text{skep}}\left(\mathcal{P}, \mathcal{Q}^{+}\right), \quad \forall q \in \mathcal{Q}^{-}: \text{facts}(q) \subseteq \mathcal{F}
$$
The Skeptic identifies legitimate operational contexts (maintenance windows, known admin activity, scheduled tasks, software updates) that explain the same observations without invoking malicious intent. Critically, the Skeptic operates under the same closed-world constraint—it cannot introduce external knowledge or hypothetical evidence. The adversarial structure ensures that only verdicts surviving genuine dialectical scrutiny reach the judgment phase.

### Oracle Judge (Synthesis Phase — Deterministic)

The Oracle Judge is a pure function—not an LLM agent—that computes the final verdict $V$ deterministically from the Architect and Skeptic positions:
$$
V = \text{Oracle}_{\text{judge}}\left(\mathcal{Q}^{+}, \mathcal{Q}^{-}, \mathcal{P}\right) \in \{\texttt{THREAT\_CONFIRMED}, \texttt{THREAT\_DISMISSED}, \texttt{INCONCLUSIVE}\}
$$
The decision boundary is defined by confidence thresholds $\tau_c = 0.7$ (confirmation) and $\tau_d = 0.7$ (dismissal), with a weak-opposition gate $\tau_w = 0.5$:

$$
V = \begin{cases}
\texttt{CONFIRMED} & \text{if } \gamma_{\text{arch}} \geq \tau_c \wedge \gamma_{\text{skep}} < \tau_w \\
\texttt{DISMISSED} & \text{if } \gamma_{\text{skep}} \geq \tau_d \wedge \gamma_{\text{arch}} < \tau_w \\
\texttt{CONFIRMED} & \text{if } \gamma_{\text{arch}} \geq \tau_c \wedge |\mathcal{F}_{\text{arch}}| > 2|\mathcal{F}_{\text{skep}}| \\
\texttt{DISMISSED} & \text{if } \gamma_{\text{skep}} \geq \tau_d \wedge |\mathcal{F}_{\text{skep}}| > 2|\mathcal{F}_{\text{arch}}| \\
\texttt{INCONCLUSIVE} & \text{otherwise}
\end{cases}
$$

The overall verdict confidence is computed as $\gamma_V = \frac{\gamma_{\text{arch}} + \gamma_{\text{skep}}}{2}$ weighted by the evidence density of the prevailing side. This deterministic design eliminates LLM stochasticity from the judgment layer—the Oracle cannot hallucinate, equivocate, or be prompt-injected.

### Oracle Narrator (Resolution Phase)

The Oracle Narrator produces a human-readable explanation of the verdict without the authority to modify it:
$$
N = \text{Agent}_{\text{narr}}\left(V, \mathcal{Q}^{+}, \mathcal{Q}^{-}, \mathcal{P}\right), \quad \text{s.t. } V \text{ is locked}
$$
The narrative $N$ is explicitly low-trust output—it explains the reasoning chain but is never used as input to any downstream decision. This separation ensures that persuasive language cannot override evidence-grounded verdicts.

### Miscalibration Detector (Post-Verdict Audit)

After verdict computation, a Miscalibration Detector evaluates whether the system exhibits overconfidence relative to evidence quality:
$$
\text{Flag} = \text{Detect}_{\text{misc}}\left(V, \mathcal{Q}^{+}, \mathcal{Q}^{-}, \mathcal{P}\right) \rightarrow \{(\text{flagged}, \text{patterns}, r_{\text{risk}})\}
$$
If flagged, a Claim Auditor performs fine-grained assertion-level validation, classifying each claim as supported, weak, or unsupported against the evidence packet. This two-stage audit provides calibration feedback without modifying the verdict.

### Visual Emitter (Observation Layer)

The Visual Emitter transforms the analysis pipeline into a temporal event stream $\mathcal{V} = \{v_t\}_{t=1}^{T}$ suitable for real-time 3D rendering:
$$
\mathcal{V} = \text{Replay}\left(\mathcal{P}, \mathcal{Q}^{+}, V, \text{Detect}_{\text{misc}}\right), \quad v_t \in \{\texttt{fact}, \texttt{assertion}, \texttt{verdict}, \texttt{miscal}, \texttt{audit}\}
$$
Each event $v_t$ is a frozen dataclass serialized to JSON and streamed via WebSocket to the nw\_wrld visualization engine (Electron + Three.js), where facts render as colored spheres (by source type), assertions as icosahedra connected to cited facts, and verdicts as a central torus. An ambient particle system encodes overall confidence state. The visual layer renders exclusively from frozen data—every node, edge, and color maps to an immutable dataclass field.

### Key Experimental Finding: Single-Turn Dominance

Extensive experimentation across the 33-scenario corpus established that multi-turn dialectical debate degrades accuracy in all configurations tested:

| Configuration | Accuracy | Cost |
|---|---|---|
| Single-turn LLM $v_2$ | **72.7%** (33 scenarios) | $0.32 |
| Multi-turn (3 rounds) | 83.3% → 75.0% (12-scenario subset) | $0.31 |
| Rule-based baseline | 60.6% | $0.00 |

Misclassification diagnosis across the 9 failure cases revealed three root causes: confidence calibration errors (4 cases, 44%), evidence coverage gaps (3 cases, 33%), and ambiguity mismatches where system behavior is arguably defensible (2 cases, 22%). Zero verdict inversions. Zero runtime errors. The debate chapter is formally closed—single-turn is the production path, and the next accuracy lever is prompt engineering informed by per-scenario failure mode classification.
