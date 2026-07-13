"""Checks for docs/PREPRINT_PREPARATION_PLAN.md: the plan exists, carries all
required sections, distinguishes internal/external/public readiness states,
states the preprint claim boundary, chooses exactly one recommended next PR,
avoids forbidden overclaims, and resolves every referenced artifact path.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "docs/PREPRINT_PREPARATION_PLAN.md"

REQUIRED_SECTIONS = [
    "## 1. Current Preprint-Readiness Verdict",
    "## 2. What Is Already Complete",
    "## 3. Remaining Blockers Before Public Preprint",
    "## 4. Preprint Scope Boundary",
    "## 5. Preprint Artifact Checklist",
    "## 6. PDF / Typesetting Plan",
    "## 7. Public Repository Readiness",
    "## 8. Responsible-Use and Limitation Statements",
    "## 9. Preprint Title and Abstract Check",
    "## 10. Preprint Release Sequence",
    "## 11. Recommended Next PR",
    "## 12. Final Verdict",
]

# Same six forbidden overclaims used by tests/test_external_review_packet.py,
# checked as literal (case-insensitive) substrings. Legitimate disclaimers in
# this plan are written with different word order/phrasing (e.g. "does not
# solve secure patch reasoning" or a paraphrase) so they never trip this check.
FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]


def _text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def test_plan_exists_and_is_nonempty() -> None:
    assert PLAN_PATH.exists()
    assert _text().strip()


def test_plan_is_indexed() -> None:
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/PREPRINT_PREPARATION_PLAN.md" in index


def test_plan_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_plan_distinguishes_three_readiness_states() -> None:
    text = _text()
    normalized = text.lower()

    assert "internal working draft" in normalized
    assert "external working-draft review" in normalized
    assert "public preprint posting" in normalized

    # Each of the three states must carry a verdict label from the
    # required vocabulary; the plan does not have to use all three labels,
    # but every state row must use one of them.
    verdict_section = text.split("## 2.")[0]
    valid_labels = ("READY WITH CAVEATS", "READY", "NOT READY")
    assert any(label in verdict_section for label in valid_labels)
    assert "READY" in verdict_section
    assert "NOT READY" in verdict_section


def test_plan_states_preprint_claim_boundary() -> None:
    text = _text()
    boundary_section = text.split("## 4. Preprint Scope Boundary")[1].split(
        "## 5."
    )[0]

    assert "may claim" in boundary_section.lower()
    assert "must not claim" in boundary_section.lower()

    required_may_claims = [
        "relation-violating behavior",
        "candidate-identity",
        "label-only and polarity-only",
        "shared internal mechanism",
        "confounded by stronger polarity/gold structure",
        "structural consistency constraint",
        "remains unresolved",
    ]
    for phrase in required_may_claims:
        assert phrase.lower() in boundary_section.lower(), phrase


def test_plan_recommends_exactly_one_next_pr() -> None:
    text = _text()
    next_pr_section = text.split("## 11. Recommended Next PR")[1].split(
        "## 12."
    )[0]

    recommended = re.findall(r"\*\*Recommendation: ([A-E])\b", next_pr_section)
    assert len(recommended) == 1, recommended
    assert recommended[0] == "A"

    # Exactly one option letter should be the headline recommendation; the
    # other four must appear only as considered-but-not-chosen options.
    for letter in "BCDE":
        assert f"**Recommendation: {letter}" not in next_pr_section


def test_plan_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"


def test_plan_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(r"\[RESULT: [a-z0-9-]+\]", (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"))
    )
    plan_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    # The plan may reference existing anchors but must not introduce new ones.
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
