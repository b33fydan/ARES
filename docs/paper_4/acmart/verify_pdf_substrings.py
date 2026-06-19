"""Paper 4 — pdftotext substring verification gate.

The compiled sigconf PDF (the *submitted* artifact, not just the
markdown) must contain every value in
``docs.paper_4.number_check.prose_substring_claims()``. Run this after
every recompile to catch regressions where prose or rendering accidentally
drops a locked substring (e.g. a dollar amount mangled by escaping).

Usage::

    python docs/paper_4/acmart/verify_pdf_substrings.py

Or with a custom PDF path::

    python docs/paper_4/acmart/verify_pdf_substrings.py path/to/paper.pdf

Exit code 0 on PASS, 1 on FAIL, 2 if the PDF is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PDF = REPO_ROOT / "docs" / "paper_4" / "acmart" / "paper_4_acmart.pdf"


def locked_substrings() -> tuple[str, ...]:
    """The load-bearing substrings the PDF must contain — single source of
    truth is the Paper 4 number-check (skeleton-seeded)."""
    sys.path.insert(0, str(REPO_ROOT))
    from docs.paper_4.number_check import prose_substring_claims  # noqa: E402

    return prose_substring_claims()


def missing_substrings(text: str, locked: Iterable[str]) -> list[str]:
    """Return the locked substrings absent from ``text`` (order preserved)."""
    return [s for s in locked if s not in text]


def _resolve_pdftotext() -> str:
    pdftotext = shutil.which("pdftotext")
    if pdftotext is not None:
        return pdftotext
    # MiKTeX ships pdftotext alongside pdflatex.
    candidate = (
        Path.home() / "AppData" / "Local" / "Programs" / "MiKTeX"
        / "miktex" / "bin" / "x64" / "pdftotext.exe"
    )
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError("pdftotext not found on PATH or in MiKTeX install")


def extract_pdf_text(pdf_path: Path) -> str:
    """Run pdftotext on the PDF and return the extracted text."""
    pdftotext = _resolve_pdftotext()
    with tempfile.NamedTemporaryFile(
        suffix=".txt", delete=False, mode="w", encoding="utf-8",
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        subprocess.run(
            [pdftotext, "-layout", str(pdf_path), str(tmp_path)],
            check=True, capture_output=True,
        )
        return tmp_path.read_text(encoding="utf-8", errors="replace")
    finally:
        tmp_path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    pdf_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_PDF
    if not pdf_path.exists():
        print(f"PDF not found: {pdf_path}", file=sys.stderr)
        return 2

    locked = locked_substrings()
    text = extract_pdf_text(pdf_path)

    print(f"Verifying {len(locked)} locked substrings against {pdf_path.name}")
    print(f"{'Substring':<25} | Status | Count")
    print("-" * 50)
    missing: list[str] = []
    for s in locked:
        count = text.count(s)
        status = "PASS" if count > 0 else "FAIL"
        if count == 0:
            missing.append(s)
        label = s if len(s) <= 23 else s[:20] + "..."
        print(f"{label!r:<25} | {status:6} | {count}")

    print()
    passed = len(locked) - len(missing)
    print(f"VERDICT: {passed} / {len(locked)} substrings present in PDF")
    if missing:
        print(f"MISSING: {missing}")
        return 1
    print("PASS - all locked substrings present in submitted artifact")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv))
