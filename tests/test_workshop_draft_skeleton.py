"""Checks for paper/workshop_draft_skeleton.md: the skeleton exists, states
the central thesis, contains all required body sections and figure/table
callouts, preserves the candidate-identity/directional-patch and
responsible-use boundaries, avoids forbidden overclaims, adds no new
[RESULT: ...] anchors, and notes both the SaTML 2027 re-check requirement
and the Table 3 supplement-with-body-contrast-preserved decision.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKELETON_PATH = ROOT / "paper/workshop_draft_skeleton.md"

REQUIRED_BODY_SECTIONS = [
    "## 1. Introduction and Motivation",
    "## 2. Task Formulation and Evaluation Threat",
    "## 3. VeriPatch-RR Evaluation Design",
    "## 4. Label-vs-Polarity Results",
    "## 5. Cross-Source and Cross-Architecture Checks",
    "## 6. Repair Decomposition",
    "## 7. Limitations and Responsible Use",
]

REQUIRED_FIGURE_TABLE_CALLOUTS = [
    "[Figure 1 here]",
    "[Figure 5 here]",
    "[Table 2 here]",
    "[Figure 7 here]",
    "[Table 4 here]",
]

FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]


def _text() -> str:
    return SKELETON_PATH.read_text(encoding="utf-8")


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_skeleton_exists_and_is_nonempty() -> None:
    assert SKELETON_PATH.exists()
    assert _text().strip()


def test_skeleton_contains_central_thesis() -> None:
    normalized = _normalized_whitespace(_text())
    assert (
        "Pointwise secure-code accuracy can hide relation-violating "
        "behavior induced by patch presentation structure" in normalized
    )


def test_skeleton_has_all_required_body_sections() -> None:
    text = _text()
    for heading in REQUIRED_BODY_SECTIONS:
        assert heading in text, heading


def test_skeleton_has_figure_table_callouts() -> None:
    text = _text()
    for callout in REQUIRED_FIGURE_TABLE_CALLOUTS:
        assert callout in text, callout


def test_skeleton_preserves_candidate_identity_boundary() -> None:
    normalized = _text().lower()
    assert "candidate-identity" in normalized
    assert "directional" in normalized


def test_skeleton_includes_responsible_use_boundary() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "does not replace human security review" in normalized
    assert "not a deployed vulnerability scanner" in normalized


def test_skeleton_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"


def test_skeleton_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    skeleton_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert skeleton_anchors <= draft_anchors


def test_skeleton_notes_satml_2027_requirements_must_be_rechecked() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "satml 2027" in normalized
    assert "not yet published" in normalized
    assert "re-checked" in normalized or "re-check" in normalized


def test_skeleton_notes_table3_supplement_with_body_contrast_preserved() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "table 3" in normalized
    assert "supplement" in normalized
    assert "0.706" in normalized and "0.855" in normalized
