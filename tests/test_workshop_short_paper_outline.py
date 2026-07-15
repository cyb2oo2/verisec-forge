"""Checks for paper/workshop_short_paper_outline.md: the outline exists,
targets SaTML 2027 with a re-verification caveat on the deadline, states a
one-sentence thesis, limits contributions to 3-4, defines figure/table
selection, claim boundaries, and reviewer-risk analysis, recommends exactly
one next PR, avoids forbidden overclaims, and adds no new result anchors.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTLINE_PATH = ROOT / "paper/workshop_short_paper_outline.md"

REQUIRED_SECTIONS = [
    "## 1. Target and Status",
    "## 2. One-Sentence Thesis",
    "## 3. Intended Contribution List",
    "## 4. Proposed Paper Structure",
    "## 5. Figure/Table Selection",
    "## 6. What to Compress",
    "## 7. Claim-Boundary Checklist",
    "## 8. Reviewer-Risk Analysis",
    "## 9. Submission Preparation Blockers",
    "## 10. Recommended Next PR",
]

FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
    "a definitive benchmark",
    "rely on diff polarity internally",
    "repair solves the issue",
    "repair solved the issue",
    "crossvul shows better generalization",
]


def _text() -> str:
    return OUTLINE_PATH.read_text(encoding="utf-8")


def test_outline_exists_and_is_nonempty() -> None:
    assert OUTLINE_PATH.exists()
    assert _text().strip()


def test_outline_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_outline_targets_satml_2027() -> None:
    section = _text().split("## 1. Target and Status")[1].split("## 2.")[0]
    assert "SaTML 2027" in section


def test_outline_deadline_has_reverification_caveat() -> None:
    section = _text().split("## 1. Target and Status")[1].split("## 2.")[0]
    assert "September 29, 2026" in section
    normalized = section.lower()
    assert "not yet published" in normalized
    assert "re-check" in normalized or "re-verify" in normalized


def test_outline_states_one_sentence_thesis() -> None:
    section = _text().split("## 2. One-Sentence Thesis")[1].split("## 3.")[0]
    lines = [line.lstrip("> ").rstrip() for line in section.splitlines()]
    normalized = re.sub(r"\s+", " ", " ".join(lines))
    assert (
        "Pointwise secure-code accuracy can hide relation-violating "
        "behavior induced by patch presentation structure" in normalized
    )


def test_outline_limits_contributions_to_three_or_four() -> None:
    section = _text().split("## 3. Intended Contribution List")[1].split(
        "## 4."
    )[0]
    rows = re.findall(r"^\|\s*\d+\s*\|", section, flags=re.MULTILINE)
    assert 3 <= len(rows) <= 4, rows


def test_outline_has_figure_table_selection() -> None:
    section = _text().split("## 5. Figure/Table Selection")[1].split("## 6.")[0]
    for item in ["Figure 1", "Figure 5", "Figure 7", "Table 2", "Table 3", "Table 4"]:
        assert item in section, item


def test_outline_has_claim_boundaries() -> None:
    section = _text().split("## 7. Claim-Boundary Checklist")[1].split("## 8.")[0]
    assert "Do not claim" in section
    assert "human review" in section.lower()


def test_outline_has_reviewer_risk_analysis() -> None:
    section = _text().split("## 8. Reviewer-Risk Analysis")[1].split("## 9.")[0]
    for objection in [
        "internal mechanism",
        "Limited model families",
        "artificial",
        "deployed security tool",
        "structural",
        "confound",
    ]:
        assert objection.lower() in section.lower(), objection


def test_outline_recommends_exactly_one_next_pr() -> None:
    text = _text()
    section = text.split("## 10. Recommended Next PR")[1]

    recommended = re.findall(r"\*\*Recommendation: ([A-E])\b", section)
    assert len(recommended) == 1, recommended
    assert recommended[0] == "A"

    for letter in "BCDE":
        assert f"**Recommendation: {letter}" not in section


def test_outline_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"


def test_outline_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    outline_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert outline_anchors <= draft_anchors
