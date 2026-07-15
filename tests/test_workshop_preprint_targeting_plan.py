"""Checks for docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md: the plan exists,
carries all required sections, distinguishes workshop review from preprint
dissemination, chooses a primary audience and a default strategy, defines
the venue-search protocol, chooses exactly one recommended next PR, avoids
forbidden overclaims, and resolves every referenced artifact path.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md"

REQUIRED_SECTIONS = [
    "## 1. Goal of This Line",
    "## 2. Current Artifact Readiness",
    "## 3. Candidate Audience Categories",
    "## 4. Best-Fit Positioning",
    "## 5. Workshop vs. Preprint Strategy",
    "## 6. What the Workshop Paper Should Look Like",
    "## 7. What Not to Claim",
    "## 8. Venue-Search Protocol",
    "## 9. Candidate Venue Shortlisting Plan",
    "## 10. Preprint Release Decision",
    "## 11. Recommended Next PR",
    "## 12. Final Recommendation",
]

# The six forbidden overclaims shared with tests/test_external_review_packet.py
# and tests/test_preprint_preparation_plan.py, plus four phrasings this
# document was specifically asked to avoid (Section 7's "Also avoid" list).
# All are checked as literal (case-insensitive) substrings; legitimate
# disclaimers in this plan are written as negated paraphrases so none of
# them ever trip this check.
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
    return PLAN_PATH.read_text(encoding="utf-8")


def test_plan_exists_and_is_nonempty() -> None:
    assert PLAN_PATH.exists()
    assert _text().strip()


def test_plan_is_indexed() -> None:
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md" in index


def test_plan_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_plan_distinguishes_workshop_review_from_preprint_dissemination() -> None:
    goal_section = _text().split("## 1. Goal of This Line")[1].split("## 2.")[0]
    normalized = goal_section.lower()

    assert "workshop review is external feedback" in normalized
    assert "preprint" in normalized and "visibility" in normalized
    assert "not review" in normalized or "not a review" in normalized


def test_plan_chooses_a_primary_audience() -> None:
    positioning_section = _text().split("## 4. Best-Fit Positioning")[1].split(
        "## 5."
    )[0]
    assert "Primary Target Audience" in positioning_section
    # exactly one of the two positionings should be named the primary target
    assert "Positioning A (AI for Code" in positioning_section
    assert re.search(r"is the primary\s+target", positioning_section)


def test_plan_chooses_a_default_strategy() -> None:
    strategy_section = _text().split("## 5. Workshop vs. Preprint Strategy")[1].split(
        "## 6."
    )[0]
    assert re.search(r"\*\*Default: Option [ABC]", strategy_section)
    assert "When another option would be better" in strategy_section


def test_plan_defines_venue_search_protocol() -> None:
    protocol_section = _text().split("## 8. Venue-Search Protocol")[1].split(
        "## 9."
    )[0]
    required_fields = [
        "Workshop name",
        "Parent conference",
        "Year",
        "Deadline (submission)",
        "Notification date",
        "Page limit",
        "Anonymity policy",
        "Preprint / dual-submission policy",
        "Scope fit",
        "Archival status",
        "Short papers / extended abstracts accepted",
        "Code / artifact submission encouraged",
    ]
    for field in required_fields:
        assert field in protocol_section, field
    assert "official CFP" in protocol_section


def test_plan_recommends_exactly_one_next_pr() -> None:
    text = _text()
    next_pr_section = text.split("## 11. Recommended Next PR")[1].split("## 12.")[0]

    recommended = re.findall(r"\*\*Recommendation: ([A-E])\b", next_pr_section)
    assert len(recommended) == 1, recommended
    assert recommended[0] == "B"

    for letter in "ACDE":
        assert f"**Recommendation: {letter}" not in next_pr_section


def test_plan_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"


def test_plan_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    plan_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert plan_anchors <= draft_anchors


def test_plan_referenced_paths_resolve() -> None:
    text = _text()

    dir_pattern = re.compile(
        r"`((?:reports|docs|paper|src|scripts|reproducibility|tests)/"
        r"[A-Za-z0-9_./-]+\.(?:md|json|py|svg))`"
    )
    root_pattern = re.compile(r"`(README\.md|LICENSE|CITATION\.cff|REPRODUCIBILITY\.md)`")

    referenced = {m.split("::")[0] for m in dir_pattern.findall(text)}
    referenced |= set(root_pattern.findall(text))

    assert referenced, "plan should reference concrete artifact paths"
    for relative_path in referenced:
        assert (ROOT / relative_path).exists(), relative_path
