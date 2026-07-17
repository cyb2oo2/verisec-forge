"""Provisional, format-neutral PDF build path for the workshop draft.

Renders `paper/workshop_draft_v1.md` to `build/workshop_draft_v1.pdf` so the
project can start checking approximate page length, figure/table placement
risk, citation rendering, and references formatting -- not to produce a
SaTML-formatted submission PDF. SaTML 2027's own submission requirements
(page limit, column format, font, template) are not yet published as of
`docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`'s research date, so this script
deliberately does not attempt to match any specific venue template.

`markdown` + `weasyprint` is the recommended toolchain for this repository
(see `paper/workshop_build_notes.md`); `pandoc` is an optional alternative.
Internally this script attempts, in order: `pandoc` on PATH (requires a PDF
engine such as a LaTeX distribution, wkhtmltopdf, or weasyprint to already be
installed and discoverable by pandoc itself), then the `markdown` +
`weasyprint` Python packages -- this internal order is only a fallback
chain, not a recommendation; if only the recommended weasyprint path is
installed, pandoc is simply skipped as unavailable. If neither path is
available or usable, this script reports exactly what is missing and exits
non-zero -- it never fabricates a "success" result when no PDF was actually
produced.

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


def _probe_weasyprint() -> tuple[bool, str]:
    """Return whether the markdown+weasyprint path is importable and usable.

    A broken Windows native-library install can raise OSError while importing
    weasyprint, not ImportError. This probe catches that state so --check-only
    can keep its documented promise: validate the input and report tool
    availability without requiring a working PDF engine.
    """
    try:
        import markdown as _markdown_probe  # noqa: F401
    except ImportError as exc:
        return False, f"markdown/weasyprint not installed: {type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"markdown probe failed: {type(exc).__name__}: {exc}"

    try:
        import weasyprint as _weasyprint_probe  # noqa: F401
    except (ImportError, OSError) as exc:
        return False, f"markdown/weasyprint not usable: {type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"weasyprint probe failed: {type(exc).__name__}: {exc}"

    return True, "markdown+weasyprint importable"


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
        return False, f"pandoc invocation failed: {type(exc).__name__}: {exc}"
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
        return False, f"markdown/weasyprint not installed: {type(exc).__name__}: {exc}"
    except OSError as exc:
        return False, f"markdown/weasyprint not usable: {type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"markdown/weasyprint probe failed: {type(exc).__name__}: {exc}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        html_body = markdown_lib.markdown(input_path.read_text(encoding="utf-8"), extensions=["tables"])
        weasyprint.HTML(string=f"<html><body>{html_body}</body></html>").write_pdf(str(output_path))
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"weasyprint conversion failed: {type(exc).__name__}: {exc}"
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
        help="Report input validity, tool availability, and a structural summary; never requires a PDF engine when the input exists, always exits 0 in that case.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: input file not found: {args.input}")
        return 1

    summary = _structural_summary(args.input)
    print(f"Input: {args.input}")
    print(f"Structural summary (not a page-fit claim): {summary}")

    pandoc_available = shutil.which("pandoc") is not None
    weasyprint_path_available, weasyprint_probe_message = _probe_weasyprint()

    print(f"pandoc on PATH: {pandoc_available}")
    print(f"markdown+weasyprint importable: {weasyprint_path_available}")
    if not weasyprint_path_available:
        print(f"markdown+weasyprint probe: {weasyprint_probe_message}")

    if args.check_only:
        if not pandoc_available and not weasyprint_path_available:
            print(
                "No PDF build tool is currently available in this environment. "
                "This is a documented, expected state -- see paper/workshop_build_notes.md "
                "for install options. --check-only succeeds when the input exists "
                "and never fails only because a PDF engine is absent or broken."
            )
        print("check-only: no PDF was built.")
        return 0

    failure_messages: list[str] = []
    for attempt in (_try_pandoc, _try_weasyprint):
        ok, message = attempt(args.input, args.output)
        print(message)
        if ok:
            return 0
        failure_messages.append(message)

    print(
        "\nFAILED: no PDF was produced. Neither pandoc (with a discoverable PDF "
        "engine) nor the markdown+weasyprint Python path is available and usable "
        "in this environment. See paper/workshop_build_notes.md for install options. "
        "This script does not fabricate a success result when no PDF exists."
    )
    if failure_messages:
        print("Failure details:")
        for message in failure_messages:
            print(f"- {message}")
    return 1


if __name__ == "__main__":
    sys.exit(main())