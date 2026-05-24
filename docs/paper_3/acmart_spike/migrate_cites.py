"""One-shot script: migrate canonical-prose citation literals to
pandoc-style markers in ``docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md``.

Part B item 1 (Session 072). HTML comment blocks are protected — the
anonymization note inside the leading ``<!-- ... -->`` block contains an
illustrative ``(Gmys-Casiano, 2026)`` example that is meant to stay
human-readable as documentation; it is not a real citation.

Also reverts the two Session 071 §2 cite-form recasts (Jacovi
comma-only, Berdoz parenthetical) to natural narrative prose now that
the LaTeX renderer auto-formats markers via ``\\citep`` / ``\\citet``.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path("docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md")

PAREN_REPLACEMENTS = [
    ("(Gmys-Casiano, 2026)", "[@gmys-casiano-2026]"),
    ("(Berdoz, Rugli, and Wattenhofer, 2026)", "[@berdoz-rugli-wattenhofer-2026]"),
    ("(Jacovi, Goldberg, 2020)", "[@jacovi-goldberg-2020]"),
]

NARRATIVE_REPLACEMENTS = [
    ("Guo et al. (2024)", "@guo-2024"),
    ("Greshake et al. (2023)", "@greshake-2023"),
    ("Reiter (1978)", "@reiter-1978"),
]


def strip_html_comments_with_positions(text):
    """Return list of (start, end) char positions of HTML comments."""
    positions = []
    for m in re.finditer(r"<!--.*?-->", text, re.DOTALL):
        positions.append((m.start(), m.end()))
    return positions


def is_inside_any_range(pos, ranges):
    for s, e in ranges:
        if s <= pos < e:
            return True
    return False


def replace_outside_comments(text, find, replace):
    """Replace ``find`` with ``replace`` everywhere EXCEPT inside HTML comments."""
    comment_ranges = strip_html_comments_with_positions(text)
    out = []
    i = 0
    count = 0
    while i < len(text):
        idx = text.find(find, i)
        if idx == -1:
            out.append(text[i:])
            break
        if is_inside_any_range(idx, comment_ranges):
            out.append(text[i:idx + len(find)])
            i = idx + len(find)
            continue
        out.append(text[i:idx])
        out.append(replace)
        i = idx + len(find)
        count += 1
    return "".join(out), count


def main():
    text = SRC.read_text(encoding="utf-8")
    original_text = text

    print("=== Parenthetical migrations ===")
    for find, replace in PAREN_REPLACEMENTS:
        text, n = replace_outside_comments(text, find, replace)
        print(f"  {find!r} -> {replace!r}: {n} replaced")

    print()
    print("=== Narrative migrations ===")
    for find, replace in NARRATIVE_REPLACEMENTS:
        text, n = replace_outside_comments(text, find, replace)
        print(f"  {find!r} -> {replace!r}: {n} replaced")

    print()
    print("=== §2 recast reverts ===")
    # Jacovi: parenthetical recast -> narrative
    jacovi_old = (
        "To name this property requires vocabulary from the faithfulness "
        "literature in explainable AI. Faithfulness has been formalized as "
        "a quality criterion in this literature [@jacovi-goldberg-2020]: "
        "an interpretable NLP system's explanation must be a faithful "
        "representation of the underlying computation, and explanations "
        "diverging from the computation fail the criterion regardless of "
        "their surface plausibility."
    )
    jacovi_new = (
        "To name this property requires vocabulary from the faithfulness "
        "literature in explainable AI. @jacovi-goldberg-2020 formalize "
        "faithfulness as a quality criterion in this literature: an "
        "interpretable NLP system's explanation must be a faithful "
        "representation of the underlying computation, and explanations "
        "diverging from the computation fail the criterion regardless of "
        "their surface plausibility."
    )
    if jacovi_old in text:
        text = text.replace(jacovi_old, jacovi_new)
        print("  Jacovi recast: reverted to narrative form")
    else:
        print("  Jacovi recast: NO MATCH — manual inspection needed")

    # Berdoz: §2 parenthetical recast -> narrative. Only the §2 instance
    # (line 43-44); §6.5 / §7.4 / §8.4 stay parenthetical per CLAUDE.md.
    berdoz_old = (
        "An adjacent question has been approached from a different "
        "methodological vantage [@berdoz-rugli-wattenhofer-2026], with "
        "substantive inter-agent disagreement reported among LLM agents "
        "in synthetic debate scenarios and convergence to agreement "
        "failing on a meaningful fraction of trials."
    )
    berdoz_new = (
        "@berdoz-rugli-wattenhofer-2026 approached an adjacent question "
        "from a different methodological vantage, with substantive "
        "inter-agent disagreement reported among LLM agents in synthetic "
        "debate scenarios and convergence to agreement failing on a "
        "meaningful fraction of trials."
    )
    if berdoz_old in text:
        text = text.replace(berdoz_old, berdoz_new)
        print("  Berdoz §2 recast: reverted to narrative form")
    else:
        print("  Berdoz §2 recast: NO MATCH — manual inspection needed")

    print()
    print(f"Source size: {len(original_text)} -> {len(text)} chars "
          f"(diff {len(text) - len(original_text):+d})")

    # Sanity check: confirm no literal cite forms remain in body (outside HTML comments)
    comment_ranges = strip_html_comments_with_positions(text)
    body_chars = "".join(
        ch for i, ch in enumerate(text)
        if not is_inside_any_range(i, comment_ranges)
    )

    print()
    print("=== Sanity: cite literals remaining in body (outside HTML comments) ===")
    for find, _ in PAREN_REPLACEMENTS + NARRATIVE_REPLACEMENTS:
        if find in body_chars:
            print(f"  REMAINING: {find!r}")
    print("  (none should appear)")

    print()
    print("=== Marker presence in body ===")
    import re as _re
    paren_re = _re.compile(r"\[@([a-z0-9\-]+)\]")
    narr_re = _re.compile(r"(?<![a-zA-Z0-9_])@([a-z0-9\-]+)\b")
    paren_count = len(paren_re.findall(body_chars))
    narr_count = len(narr_re.findall(body_chars))
    print(f"  Parenthetical markers: {paren_count}")
    print(f"  Narrative markers: {narr_count}")

    SRC.write_text(text, encoding="utf-8")
    print()
    print(f"Wrote {SRC}")


if __name__ == "__main__":
    main()
