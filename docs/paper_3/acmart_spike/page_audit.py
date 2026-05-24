"""Spike measurement audit — parse .aux and report:
- Section / subsection start pages
- Figure caption pages
- end-of-body / end-of-bib / end-of-appendix boundary labels
- Overall PDF page count (from pdfinfo)

Output goes to stdout in a compact human-readable table format.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

AUX = Path(__file__).parent / "paper_3_acmart.aux"
PDF = Path(__file__).parent / "paper_3_acmart.pdf"


def main() -> int:
    text = AUX.read_text(encoding="utf-8")

    section_re = re.compile(
        r"@writefile\{toc\}\{\\contentsline\s+\{(section|subsection)\}"
        r"\{(\\numberline\s+\{([\d\.]+)\})?\s*([^{}]+?)\}"
        r"\{(\d+)\}"
    )
    fig_re = re.compile(
        r"@writefile\{lof\}\{\\contentsline\s+\{figure\}"
        r"\{\\numberline\s+\{(\d+)\}\{\\ignorespaces ([^}]+?)\}\}"
        r"\{(\d+)\}"
    )
    end_re = re.compile(r"newlabel\{end-of-(body|bib|appendix)\}\{\{[^}]*\}\{(\d+)\}")

    print("=== Section / subsection start pages ===")
    for m in section_re.finditer(text):
        kind = m.group(1)
        num = m.group(3) or ""
        title = m.group(4).strip()
        page = m.group(5)
        indent = "  " if kind == "section" else "    "
        label = f"§{num} {title}" if num else title
        print(f"{indent}{label:55} page {page}")

    print()
    print("=== Figure caption pages ===")
    for m in fig_re.finditer(text):
        fig_num = m.group(1)
        title = m.group(2).strip()[:60]
        page = m.group(3)
        print(f"  Fig {fig_num}: {title}... -> page {page}")

    print()
    print("=== End-of-* boundary labels ===")
    for m in end_re.finditer(text):
        print(f"  end-of-{m.group(1):10}: page {m.group(2)}")

    print()
    print("=== PDF metadata ===")
    if PDF.exists():
        try:
            out = subprocess.run(
                ["pdfinfo", str(PDF)],
                capture_output=True, text=True, check=False,
            )
            for line in out.stdout.splitlines():
                if line.startswith("Pages:") or line.startswith("Page size:"):
                    print(f"  {line}")
        except FileNotFoundError:
            print("  (pdfinfo unavailable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
