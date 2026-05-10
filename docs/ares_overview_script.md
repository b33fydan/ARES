# ARES Overview — Excalidraw Walkthrough Script

Companion to `ares_overview.excalidraw` / `ares_overview.png`.
Three sections, one punchline. Walk left-to-right, top-to-bottom.

---

## Section 1 — Core Pipeline (top)

**Beat:** "Evidence comes in sealed. Architect analyzes. Firewall checks the *shape*. If it's clean, Skeptic challenges and Oracle decides. If tainted — dashed red loop — we throw the Architect away and start fresh on raw evidence."

**Color grammar to mention once:**

- Cyan = data (the EvidencePacket — SHA256-sealed, immutable)
- Blue / purple / green = LLM agents (Architect, Skeptic, Oracle)
- Red = the deterministic gate (no LLM, just Python)
- Orange = the final immutable verdict

---

## Section 2 — A Schema Up Close (middle)

**Beat:** "Here's what a schema actually *is* — a `@dataclass(frozen=True)` with named, typed fields. Padlocks because nothing can be mutated after construction. The orange box on the right is a *producer invariant*: if `passed=False`, the class *must* receive a sanitized fallback. The class refuses to exist otherwise."

**Closing line (already on canvas):** "Every agent speaks this shape. If they don't, the next agent literally cannot read them."

---

## Section 3 — What the Firewall Catches (bottom)

**Beat:** Walk left to right through the four cards.

> "Wrong type. Self-contradiction. Phantom citation. Invariant break. All four caught deterministically — zero LLM calls, zero ambiguity."

The dashed red bar underneath all four reinforces the rejection.

---

## The punchline (gold footer — biggest moment of the video)

> "Schema catches structure — 100%. It does not catch *semantic framing* — 0%. A perfectly-shaped, grammatically valid lie walks right past. **That's Finding 7. That's the heart of Paper 2.**"

**Optional follow-on (the data-integrity reframe added to Paper 2 v1.2):**

> "Deterministic verification doesn't eliminate semantic attacks — it converts them into data integrity attacks. That's a smaller, more legible problem, and it composes with traditional security tools."

---

## Production notes

- Hold on the gold footer for ~2 seconds before cutting. It's the line viewers will quote.
- If pacing runs long, drop the color-grammar enumeration in Section 1. The visual is self-evident.
- Sections 2 and 3 can stand alone as standalone clips for short-form.
