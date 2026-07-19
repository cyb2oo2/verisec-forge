"""Checks for the weasyprint-preferred toolchain documentation in
paper/workshop_build_notes.md: markdown + weasyprint is recommended as the
preferred provisional toolchain, pandoc remains documented as optional
(not default), an install command is present, Windows native-library
install instructions (MSYS2/pacman/WEASYPRINT_DLL_DIRECTORIES) are
present, the resolved MSYS2-prerequisite status (PR #85 then its
follow-up) is documented, the output is stated as generic/not-SaTML-
formatted, generated PDFs are stated as not committed, no page fit is
claimed, no new [RESULT: ...] anchors were added, and no forbidden
overclaims appear.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTES_PATH = ROOT / "paper/workshop_build_notes.md"

FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]


def _text() -> str:
    return NOTES_PATH.read_text(encoding="utf-8")


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_notes_recommend_weasyprint_as_preferred_toolchain() -> None:
    text = _text()
    assert "Recommended provisional toolchain: markdown + weasyprint" in text
    normalized = _normalized_whitespace(text).lower()
    assert "preferred default for this repository" in normalized


def test_notes_document_pandoc_as_optional() -> None:
    text = _text()
    assert "Optional alternative: pandoc" in text
    section = text.split("### Optional alternative: pandoc")[1]
    assert "Not the default" in section


def test_notes_include_install_command() -> None:
    section = _text().split("### Recommended provisional toolchain")[1].split(
        "### Optional alternative"
    )[0]
    assert "pip install markdown weasyprint" in section


def test_notes_include_windows_native_library_instructions() -> None:
    section = _text().split("### Recommended provisional toolchain")[1].split(
        "### Optional alternative"
    )[0]
    assert "libgobject-2.0-0" in section
    assert "Pango" in section
    assert "GObject" in section
    assert "MSYS2" in section
    assert "pacman -S mingw-w64-x86_64-pango" in section
    assert "WEASYPRINT_DLL_DIRECTORIES" in section
    assert 'python -c "import markdown; import weasyprint"' in section


def test_notes_document_resolved_msys2_prerequisite() -> None:
    section = _text().split("### Recommended provisional toolchain")[1].split(
        "### Optional alternative"
    )[0]
    assert "paper/workshop_weasyprint_msys2_install_report.md" in section
    assert "paper/workshop_weasyprint_msys2_resolved_report.md" in section
    normalized = _normalized_whitespace(section).lower()
    assert "msys2 is now installed" in normalized
    assert "`pacman -s mingw-w64-x86_64-pango` now succeeds" in normalized
    assert "the `libgobject-2.0-0` load failure is now resolved on that machine" in normalized
    assert "a pdf was produced" in normalized
    assert "does not mean page fit or satml formatting have been validated" in normalized
    assert "per-machine, not a repository-wide guarantee" in normalized


def test_current_limitations_points_to_msys2_resolved_report() -> None:
    section = _text().split("## Current Limitations")[1].split("## Why This Is Provisional")[0]
    assert "paper/workshop_weasyprint_msys2_install_report.md" in section
    assert "paper/workshop_weasyprint_msys2_resolved_report.md" in section
    normalized = _normalized_whitespace(section).lower()
    assert "installed manually and the native-library fix confirmed working" in normalized
    assert "per-machine prerequisite" in normalized


def test_notes_state_output_is_generic_not_satml_formatted() -> None:
    section = _text().split("### Recommended provisional toolchain")[1].split(
        "### Optional alternative"
    )[0]
    normalized = _normalized_whitespace(section).lower()
    assert "generic" in normalized
    assert "not satml-formatted" in normalized


def test_notes_state_generated_pdfs_not_committed() -> None:
    section = _text().split("### Recommended provisional toolchain")[1].split(
        "### Optional alternative"
    )[0]
    normalized = _normalized_whitespace(section).lower()
    assert "not committed" in normalized
    assert "git-ignored" in normalized


def test_notes_do_not_claim_page_fit() -> None:
    normalized = _text().lower()
    assert "not a page-fit claim" in normalized
    assert "confirmed page fit" not in normalized
    assert "validated page fit" not in normalized


def test_weasyprint_not_added_as_project_dependency() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "weasyprint" not in pyproject.lower()


def test_no_new_result_anchors_introduced() -> None:
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    found = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", _text()))
    assert found <= draft_anchors


def test_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"
