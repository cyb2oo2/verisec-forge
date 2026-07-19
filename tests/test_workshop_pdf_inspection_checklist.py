"""Checks for paper/workshop_pdf_inspection_checklist.md: the checklist
exists, covers the required inspection items (open-without-error, page
count as a non-claim, figure/table placeholder presence, RESULT/RELATED
anchor rendering, section order, text/markdown-rendering sanity), states
explicit non-goals (no page-fit claim, no SaTML formatting claim, no
bibliography/citation-style validation), points back to the build notes
and readiness audit, adds no new [RESULT: ...] anchors, and avoids
forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKLIST_PATH = ROOT / "paper/workshop_pdf_inspection_checklist.md"
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
    return CHECKLIST_PATH.read_text(encoding="utf-8")


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("*", ""))


def test_checklist_exists_and_is_nonempty() -> None:
    assert CHECKLIST_PATH.exists()
    assert _text().strip()


def test_checklist_covers_required_items() -> None:
    section = _text().split("## Checklist")[1].split("## Explicit Non-Goals")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "does the pdf open without error" in normalized
    assert "record the raw page count" in normalized
    assert "figure placeholders present" in normalized
    assert "table placeholders present" in normalized
    assert "`[result: ...]`" in normalized
    assert "`[related: ...]`" in normalized
    assert "section headers present, numbered" in normalized
    assert "text truncation" in normalized
    assert "unrendered markdown syntax" in normalized


def test_checklist_states_explicit_non_goals() -> None:
    section = _text().split("## Explicit Non-Goals")[1].split("## Recording Results")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "claim page fit" in normalized
    assert "claim satml formatting compliance" in normalized
    assert "validate citation or bibliography formatting" in normalized
    assert "substitute for the real typeset submission build" in normalized
    assert "anonymize, submit, or prepare the draft" in normalized


def test_checklist_page_count_item_is_not_a_fit_claim() -> None:
    section = _text().split("## Checklist")[1].split("## Explicit Non-Goals")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "not a page-fit judgment" in normalized


def test_checklist_references_build_notes_and_readiness_audit() -> None:
    text = _text()
    assert "paper/workshop_build_notes.md" in text
    assert "paper/workshop_draft_v0_readiness_audit.md" in text


def test_checklist_does_not_claim_page_fit_anywhere() -> None:
    normalized = _text().lower()
    assert "confirmed page fit" not in normalized
    assert "validated page fit" not in normalized


def test_checklist_does_not_claim_satml_formatting_anywhere() -> None:
    normalized = _text().lower()
    assert "confirmed satml formatting" not in normalized
    assert "validated satml formatting" not in normalized


def test_build_notes_point_to_checklist() -> None:
    section = NOTES_PATH.read_text(encoding="utf-8").split("## Expected Output")[1].split(
        "`--check-only` also prints"
    )[0]
    assert "paper/workshop_pdf_inspection_checklist.md" in section


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
