"""Checks for paper/workshop_draft_v0_readiness_audit.md: the audit exists,
contains all required sections, uses READY/READY WITH CAVEATS/NOT READY
verdicts, includes reviewer-risk, figure/table, citation/anchor, and
page-budget audits, recommends exactly one next PR, adds no new
[RESULT: ...] anchors, and avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "paper/workshop_draft_v0_readiness_audit.md"

REQUIRED_SECTIONS = [
    "## 1. Overall Verdict",
    "## 2. What Works",
    "## 3. Biggest Weaknesses",
    "## 4. Reviewer Risk Analysis",
    "## 5. Figure/Table Audit",
    "## 6. Citation and Anchor Audit",
    "## 7. Page-Budget Audit",
    "## 8. What Should Change in v1",
    "## 9. What Not to Do Next",
    "## 10. Recommended Next PR",
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
    return AUDIT_PATH.read_text(encoding="utf-8")


def test_audit_exists_and_is_nonempty() -> None:
    assert AUDIT_PATH.exists()
    assert _text().strip()


def test_audit_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_audit_uses_required_verdict_labels() -> None:
    section = _text().split("## 1. Overall Verdict")[1].split("## 2.")[0]
    assert "READY" in section
    assert "NOT READY" in section


def test_audit_has_reviewer_risk_analysis() -> None:
    section = _text().split("## 4. Reviewer Risk Analysis")[1].split("## 5.")[0]
    for objection in [
        "artificial",
        "prompt sensitivity",
        "model families",
        "not internal",
        "CrossVul",
        "structural",
        "deployable security tool",
        "Why SaTML",
    ]:
        assert objection.lower() in section.lower(), objection


def test_audit_has_figure_table_audit() -> None:
    section = _text().split("## 5. Figure/Table Audit")[1].split("## 6.")[0]
    for item in ["Figure 1", "Figure 5", "Table 2", "Figure 7", "Table 4", "Table 3"]:
        assert item in section, item


def test_audit_has_citation_and_anchor_audit() -> None:
    section = _text().split("## 6. Citation and Anchor Audit")[1].split("## 7.")[0]
    normalized = section.lower()
    assert "no new" in normalized and "result" in normalized
    assert "result_anchor_map.md" in section
    assert "references.md" in section
    assert "fabricated" in normalized


def test_audit_has_page_budget_audit() -> None:
    section = _text().split("## 7. Page-Budget Audit")[1].split("## 8.")[0]
    normalized = section.lower()
    assert "qualitative" in normalized
    assert "no claim of" in normalized or "not a validated" in normalized


def test_audit_recommends_exactly_one_next_pr() -> None:
    text = _text()
    section = text.split("## 10. Recommended Next PR")[1]
    assert "`paper: revise workshop draft v1`" in section
    # only one PR title should be bold-recommended
    recommended = re.findall(r"\*\*Recommendation: `([^`]+)`", section)
    assert len(recommended) == 1, recommended
    assert recommended[0] == "paper: revise workshop draft v1"


def test_audit_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    audit_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert audit_anchors <= draft_anchors


def test_audit_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"
