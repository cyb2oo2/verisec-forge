"""Checks for the workshop PDF build path: the build script and build notes
exist, paper/workshop_draft_v1.md is the documented source input, the
output path is documented, the notes state SaTML 2027 requirements are not
yet published and do not claim final page fit, no generated PDF is required
to be committed, no new [RESULT: ...] anchors were added, and the weasyprint
probe handles broken native-library states gracefully.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/build_workshop_draft_pdf.py"
NOTES_PATH = ROOT / "paper/workshop_build_notes.md"


def _script_text() -> str:
    return SCRIPT_PATH.read_text(encoding="utf-8")


def _notes_text() -> str:
    return NOTES_PATH.read_text(encoding="utf-8")


def _normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("*", "")).lower()


def test_build_script_and_notes_exist() -> None:
    assert SCRIPT_PATH.exists()
    assert NOTES_PATH.exists()
    assert _script_text().strip()
    assert _notes_text().strip()


def test_workshop_draft_v1_is_the_documented_source_input() -> None:
    assert "workshop_draft_v1.md" in _script_text()
    assert "workshop_draft_v1.md" in _notes_text()


def test_output_path_is_documented() -> None:
    normalized = _notes_text().lower()
    assert "build/workshop_draft_v1.pdf" in normalized or "build\\workshop_draft_v1.pdf" in normalized
    assert "build/workshop_draft_v1.pdf" in _script_text().replace("\\", "/")


def test_notes_state_satml_2027_requirements_not_yet_published() -> None:
    normalized = re.sub(r"\s+", " ", _notes_text()).lower()
    assert "satml 2027" in normalized
    assert "not yet published" in normalized


def test_notes_do_not_claim_final_page_fit() -> None:
    normalized = _notes_text().lower()
    assert "not a page-fit claim" in normalized
    assert "confirmed page fit" not in normalized
    assert "validated page fit" not in normalized
    assert "guarantees page fit" not in normalized


def test_notes_state_generated_pdf_should_not_be_committed() -> None:
    normalized = re.sub(r"\s+", " ", _notes_text()).lower()
    assert "not committed" in normalized
    assert "git-ignored" in normalized or "gitignore" in normalized


def test_build_directory_is_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "build/" in gitignore.splitlines()


def test_build_script_has_weasyprint_native_library_probe() -> None:
    text = _script_text()
    assert "def _probe_weasyprint()" in text
    assert "OSError" in text
    assert "markdown/weasyprint not usable" in text
    assert "weasyprint_probe_message" in text


def test_compact_does_not_fall_back_to_pandoc() -> None:
    """--compact must require WeasyPrint; pandoc success would silently drop compact CSS."""
    text = _script_text()
    assert "--compact requires a usable markdown+weasyprint" in text
    # Compact branch must not append a pandoc fallback attempt.
    compact_idx = text.find("if args.compact:")
    assert compact_idx >= 0
    next_default = text.find("# Default: prefer WeasyPrint", compact_idx)
    compact_block = text[compact_idx:next_default] if next_default > compact_idx else text[compact_idx:]
    assert "_try_pandoc" not in compact_block
    assert "_try_weasyprint" in compact_block


def test_notes_document_windows_native_library_hardening() -> None:
    normalized = _normalized(_notes_text())
    assert "libgobject-2.0-0" in normalized
    assert "pango" in normalized
    assert "gobject" in normalized
    assert "msys2" in normalized
    assert "pacman -s mingw-w64-x86_64-pango" in normalized
    assert 'python -c "import markdown; import weasyprint"' in _notes_text()


def test_check_only_mode_runs_without_pdf_tooling_and_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--check-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pandoc on PATH:" in result.stdout
    assert "markdown+weasyprint importable:" in result.stdout
    assert "no pdf was built" in result.stdout.lower()


def test_full_build_never_fakes_success_when_no_tooling_available() -> None:
    import shutil

    if shutil.which("pandoc") is not None:
        return  # environment has pandoc; the honest-failure path isn't exercised here
    try:
        import markdown as _markdown_probe  # noqa: F401
        import weasyprint as _weasyprint_probe  # noqa: F401
        return  # environment has the fallback path available
    except (ImportError, OSError):
        pass
    except Exception:
        pass

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--output", str(ROOT / "build" / "test_only.pdf")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "failed" in (result.stdout + result.stderr).lower()
    assert not (ROOT / "build" / "test_only.pdf").exists()


def test_no_new_result_anchors_introduced() -> None:
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    for text in (_script_text(), _notes_text()):
        found = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
        assert found <= draft_anchors
