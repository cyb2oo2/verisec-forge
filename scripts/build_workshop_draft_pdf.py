"""Provisional, format-neutral PDF build path for the workshop draft.

Renders `paper/workshop_draft_v1.md` to `build/workshop_draft_v1.pdf` so the
project can start checking approximate page length, figure/table placement
risk, citation rendering, and references formatting -- not to produce a
SaTML-formatted submission PDF. SaTML 2027's own submission requirements
(page limit, column format, font, template) are not yet published as of
`docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`'s research date, so this script
deliberately does not attempt to match any specific venue template.

Tries, in order: `pandoc` on PATH (requires a PDF engine such as a LaTeX
distribution, wkhtmltopdf, or weasyprint to already be installed and
discoverable by pandoc itself), then the `markdown` + `weasyprint` Python
packages. If neither path is available, this script reports exactly what is
missing and exits non-zero -- it never fabricates a "success" result when no
PDF was actually produced.

Usage:
    python scripts/build_workshop_draft_pdf.py --check-only
    python scripts/build_workshop_draft_pdf.py
    python scripts/build_workshop_draft_pdf.py --input paper/workshop_draft_v1.md --output build/workshop_draft_v1.pdf
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "paper" / "workshop_draft_v1.md"
DEFAULT_OUTPUT = ROOT / "build" / "workshop_draft_v1.pdf"


def _structural_summary(markdown_path: Path) -> dict[str, int]:
    """A lightweight, mechanical structural report -- word/section/figure
    counts only. This is NOT a page-fit claim; it is a rough input to the
    qualitative page-budget judgment that belongs in
    `paper/workshop_draft_v0_readiness_audit.md`, not a substitute for it.
    """
    text = markdown_path.read_text(encoding="utf-8")
    body = text[text.find("## Abstract") : text.find("## Supplement Note")]
    words = len(re.sub(r"\[RESULT: [a-z0-9-]+\]|\[RELATED: [a-z0-9-; ]+\]|`|\*|#", "", body).split())
    sections = len(re.findall(r"^## \d+\.", text, flags=re.MULTILINE))
    figures = len(re.findall(r"\[Figure \d+ here\]", text))
    tables = len(re.findall(r"\[Table \d+ here\]", text))
    return {"body_words": words, "numbered_sections": sections, "figure_placeholders": figures, "table_placeholders": tables}


def _try_pandoc(input_path: Path, output_path: Path) -> tuple[bool, str]:
    pandoc = shutil.which("pandoc")
    if not pandoc:
        return False, "pandoc not found on PATH"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [pandoc, str(input_path), "-o", str(output_path), "--standalone"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"pandoc invocation failed: {exc}"
    if result.returncode != 0:
        return False, f"pandoc exited with code {result.returncode}: {result.stderr.strip()}"
    if not output_path.exists():
        return False, "pandoc reported success but produced no output file"
    return True, f"built via pandoc: {output_path}"


def _try_weasyprint(input_path: Path, output_path: Path) -> tuple[bool, str]:
    try:
        import markdown as markdown_lib
        import weasyprint
    except ImportError as exc:
        return False, f"markdown/weasyprint not installed ({exc})"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        html_body = markdown_lib.markdown(input_path.read_text(encoding="utf-8"), extensions=["tables"])
        weasyprint.HTML(string=f"<html><body>{html_body}</body></html>").write_pdf(str(output_path))
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"weasyprint conversion failed: {exc}"
    if not output_path.exists():
        return False, "weasyprint reported success but produced no output file"
    return True, f"built via markdown+weasyprint: {output_path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Report input validity, tool availability, and a structural summary; never requires a PDF engine, always exits 0.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: input file not found: {args.input}")
        return 1

    summary = _structural_summary(args.input)
    print(f"Input: {args.input}")
    print(f"Structural summary (not a page-fit claim): {summary}")

    pandoc_available = shutil.which("pandoc") is not None
    try:
        import markdown as _markdown_probe  # noqa: F401
        import weasyprint as _weasyprint_probe  # noqa: F401
        weasyprint_path_available = True
    except ImportError:
        weasyprint_path_available = False

    print(f"pandoc on PATH: {pandoc_available}")
    print(f"markdown+weasyprint importable: {weasyprint_path_available}")

    if args.check_only:
        if not pandoc_available and not weasyprint_path_available:
            print(
                "No PDF build tool is currently available in this environment. "
                "This is a documented, expected state -- see paper/workshop_build_notes.md "
                "for install options. --check-only never fails for this reason."
            )
        print("check-only: no PDF was built.")
        return 0

    for attempt in (_try_pandoc, _try_weasyprint):
        ok, message = attempt(args.input, args.output)
        print(message)
        if ok:
            return 0

    print(
        "\nFAILED: no PDF was produced. Neither pandoc (with a discoverable PDF "
        "engine) nor the markdown+weasyprint Python packages are available in "
        "this environment. See paper/workshop_build_notes.md for install options. "
        "This script does not fabricate a success result when no PDF exists."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
