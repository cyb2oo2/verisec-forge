"""Provisional, format-neutral PDF build path for the workshop draft.

Renders a workshop markdown draft (default `paper/workshop_draft_v1.md`) to a
PDF under `build/` so the project can check approximate page length,
figure/table placement, and citation rendering -- not to produce a
SaTML-formatted submission PDF. SaTML 2027's own submission requirements
are not yet published as of `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`'s
research date, so this script deliberately does not match any venue template.

`markdown` + `weasyprint` is the recommended toolchain
(see `paper/workshop_build_notes.md`); `pandoc` is an optional alternative.
Internally this script attempts, in order: `pandoc` on PATH, then the
`markdown` + `weasyprint` Python path. If neither path is available or
usable, the script reports exactly what is missing and exits non-zero -- it
never fabricates a "success" result when no PDF was actually produced.

Usage:
    python scripts/build_workshop_draft_pdf.py --check-only
    python scripts/build_workshop_draft_pdf.py
    python scripts/build_workshop_draft_pdf.py --input paper/workshop_draft_v1.md --output build/workshop_draft_v1.pdf
    python scripts/build_workshop_draft_pdf.py --input paper/workshop_draft_v1_4page.md \\
        --output build/workshop_draft_v1_4page.pdf --compact
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

_BODY_END_MARKERS = (
    "## Supplement Note",
    "## Claim Boundaries",
    "## Open Submission Requirements",
)

_COMPACT_CSS = """
@page { size: letter; margin: 0.6in 0.65in; }
html { font-family: "Times New Roman", Times, serif; font-size: 9.5pt; line-height: 1.22; }
body { column-count: 2; column-gap: 0.28in; }
h1 { column-span: all; font-size: 12pt; line-height: 1.2; margin: 0 0 0.35em 0; text-align: center; }
h2 { font-size: 10pt; margin: 0.7em 0 0.25em 0; break-after: avoid; }
p, li { margin: 0.25em 0; text-align: justify; hyphens: auto; }
em, i { font-style: italic; }
strong, b { font-weight: 700; }
table { width: 100%; border-collapse: collapse; font-size: 8pt; margin: 0.35em 0 0.5em 0;
        break-inside: avoid; }
th, td { border: 0.4pt solid #333; padding: 0.12em 0.25em; vertical-align: top; }
th { background: #f0f0f0; font-weight: 700; }
img { max-width: 100%; height: auto; }
code { font-family: Consolas, "Courier New", monospace; font-size: 8pt; }
hr { display: none; }
"""

_DEFAULT_CSS = """
@page { size: letter; margin: 0.85in; }
html { font-family: "Times New Roman", Times, serif; font-size: 11pt; line-height: 1.35; }
h1 { font-size: 16pt; line-height: 1.25; margin: 0 0 0.5em 0; }
h2 { font-size: 13pt; margin: 1em 0 0.4em 0; }
p { margin: 0.4em 0; }
table { width: 100%; border-collapse: collapse; font-size: 10pt; margin: 0.6em 0; }
th, td { border: 0.5pt solid #333; padding: 0.25em 0.4em; }
th { background: #f0f0f0; }
img { max-width: 100%; height: auto; }
"""


def _body_slice(text: str) -> str:
    start = text.find("## Abstract")
    if start < 0:
        return text
    end = len(text)
    for marker in _BODY_END_MARKERS:
        idx = text.find(marker)
        if idx >= 0:
            end = min(end, idx)
    return text[start:end]


def _structural_summary(markdown_path: Path) -> dict[str, int]:
    """A lightweight, mechanical structural report -- word/section/figure
    counts only. This is NOT a page-fit claim; it is a rough input to the
    qualitative page-budget judgment that belongs in
    `paper/workshop_draft_v0_readiness_audit.md`, not a substitute for it.
    """
    text = markdown_path.read_text(encoding="utf-8")
    body = _body_slice(text)
    words = len(re.sub(r"\[RESULT: [a-z0-9-]+\]|\[RELATED: [a-z0-9-; ]+\]|`|\*|#", "", body).split())
    sections = len(re.findall(r"^## \d+\.", text, flags=re.MULTILINE))
    figure_placeholders = len(re.findall(r"\[Figure \d+ here\]", text))
    table_placeholders = len(re.findall(r"\[Table \d+ here\]", text))
    embedded_figures = len(re.findall(r"!\[[^\]]*Figure \d+", text))
    embedded_tables = len(re.findall(r"\*\*Table \d+\.", text))
    return {
        "body_words": words,
        "numbered_sections": sections,
        "figure_placeholders": figure_placeholders,
        "table_placeholders": table_placeholders,
        "embedded_figures": embedded_figures,
        "embedded_tables": embedded_tables,
    }


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


def _markdown_for_pdf(input_path: Path) -> str:
    """Title + body through Supplement/Claim/Open markers (no author-tooling tail)."""
    full = input_path.read_text(encoding="utf-8")
    md_text = _body_slice(full)
    title_match = re.match(r"^(# .+)\n", full)
    if title_match and not md_text.lstrip().startswith("# "):
        md_text = title_match.group(1) + "\n\n" + md_text
    return md_text


def _try_pandoc(input_path: Path, output_path: Path) -> tuple[bool, str]:
    pandoc = shutil.which("pandoc")
    if not pandoc:
        return False, "pandoc not found on PATH"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Body-slice next to the source so pandoc resolves relative figures/.
    source_slice = input_path.parent / f".{input_path.stem}.body_slice.md"
    try:
        source_slice.write_text(_markdown_for_pdf(input_path), encoding="utf-8")
        result = subprocess.run(
            [pandoc, str(source_slice), "-o", str(output_path), "--standalone"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"pandoc invocation failed: {type(exc).__name__}: {exc}"
    finally:
        try:
            source_slice.unlink(missing_ok=True)
        except OSError:
            pass
    if result.returncode != 0:
        return False, f"pandoc exited with code {result.returncode}: {result.stderr.strip()}"
    if not output_path.exists():
        return False, "pandoc reported success but produced no output file"
    return True, f"built via pandoc (body-sliced): {output_path}"


def _try_weasyprint(
    input_path: Path, output_path: Path, *, compact: bool = False
) -> tuple[bool, str]:
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
        # Resolve relative figure paths (e.g. figures/*.svg) against the
        # markdown file's directory so embedded SVGs render when present.
        base_url = input_path.resolve().parent.as_uri() + "/"
        md_text = _markdown_for_pdf(input_path)
        html_body = markdown_lib.markdown(md_text, extensions=["tables"])
        css = _COMPACT_CSS if compact else _DEFAULT_CSS
        weasyprint.HTML(
            string=f"<html><head><meta charset='utf-8'><style>{css}</style></head>"
            f"<body>{html_body}</body></html>",
            base_url=base_url,
        ).write_pdf(str(output_path))
    except Exception as exc:  # pragma: no cover - defensive, environment-dependent
        return False, f"weasyprint conversion failed: {type(exc).__name__}: {exc}"
    if not output_path.exists():
        return False, "weasyprint reported success but produced no output file"
    mode = "compact two-column" if compact else "default single-column"
    return True, f"built via markdown+weasyprint ({mode}): {output_path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Use two-column compact CSS (closer to a 4-page workshop density). WeasyPrint only.",
    )
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
    print(f"compact layout: {args.compact}")

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

    # --compact is WeasyPrint-only: pandoc cannot apply two-column compact CSS
    # and must not silently succeed with a non-compact full-file render.
    if args.compact:
        ok, message = _try_weasyprint(args.input, args.output, compact=True)
        print(message)
        if ok:
            return 0
        failure_messages.append(message)
        print(
            "\nFAILED: --compact requires a usable markdown+weasyprint path. "
            "Pandoc is not used as a fallback for compact builds (it has no "
            "compact CSS and would produce a misleading longer PDF). "
            "See paper/workshop_build_notes.md for install options."
        )
        for message in failure_messages:
            print(f"- {message}")
        return 1

    # Default: prefer WeasyPrint (recommended; figures + CSS), then pandoc
    # body-sliced fallback.
    for attempt in (
        lambda: _try_weasyprint(args.input, args.output, compact=False),
        lambda: _try_pandoc(args.input, args.output),
    ):
        ok, message = attempt()
        print(message)
        if ok:
            return 0
        failure_messages.append(message)

    print(
        "\nFAILED: no PDF was produced. Neither the markdown+weasyprint Python "
        "path nor pandoc (with a discoverable PDF engine) is available and usable "
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