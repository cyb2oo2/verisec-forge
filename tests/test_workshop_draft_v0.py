"""Checks for paper/workshop_draft_v0.md: the draft exists, contains all
required sections, has a 150-180 word abstract, states the central thesis,
preserves the candidate-identity/directional-patch boundary, contains all
required figure/table placeholders, keeps the CrossVul key numeric contrast
in body prose, includes a supplement note, claim boundaries, and the SaTML
re-check caveat, adds no new [RESULT: ...] anchors, and avoids forbidden
overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = ROOT / "paper/workshop_draft_v0.md"

REQUIRED_SECTIONS = [
    "## 1. Introduction",
    "## 2. Task Formulation",
    "## 3. VeriPatch-RR Evaluation Design",
    "## 4. Label-vs-Polarity Findings",
    "## 5. Cross-Source and Cross-Architecture Checks",
    "## 6. Repair Decomposition",
    "## 7. Limitations and Responsible Use",
]

REQUIRED_FIGURE_TABLE_PLACEHOLDERS = [
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
    return DRAFT_PATH.read_text(encoding="utf-8")


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_draft_exists_and_is_nonempty() -> None:
    assert DRAFT_PATH.exists()
    assert _text().strip()


def test_draft_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_abstract_word_count_within_target() -> None:
    text = _text()
    match = re.search(
        r"## Abstract.*?\n\n(.*?)\n\n## 1\. Introduction", text, flags=re.DOTALL
    )
    assert match, "could not locate abstract block"
    words = match.group(1).split()
    assert 150 <= len(words) <= 180, len(words)


def test_draft_contains_central_thesis() -> None:
    normalized = _normalized_whitespace(_text())
    assert (
        "Pointwise secure-code accuracy can hide relation-violating "
        "behavior induced by patch presentation structure" in normalized
    )


def test_draft_preserves_candidate_identity_boundary() -> None:
    normalized = _text().lower()
    assert "candidate-identity" in normalized
    assert "directional" in normalized


def test_draft_has_all_figure_table_placeholders() -> None:
    text = _text()
    for placeholder in REQUIRED_FIGURE_TABLE_PLACEHOLDERS:
        assert placeholder in text, placeholder


def test_draft_keeps_crossvul_contrast_in_body_prose() -> None:
    body = _text().split("## Supplement Note")[0]
    assert "0.706" in body
    assert "0.855" in body


def test_draft_has_supplement_note() -> None:
    text = _text()
    assert "## Supplement Note" in text
    section = text.split("## Supplement Note")[1].split("## Claim Boundaries")[0]
    assert "Table 3" in section
    assert "supplement" in section.lower()


def test_draft_has_claim_boundaries() -> None:
    text = _text()
    assert "## Claim Boundaries" in text
    section = text.split("## Claim Boundaries")[1].split("## Open Submission")[0]
    assert "does not claim" in section.lower()


def test_draft_has_satml_recheck_caveat() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "satml 2027" in normalized
    assert "not yet published" in normalized
    assert "re-checked" in normalized or "re-check" in normalized


def test_draft_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    workshop_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert workshop_anchors, "draft should cite existing result anchors"
    assert workshop_anchors <= draft_anchors


def test_draft_related_anchors_exist_in_references() -> None:
    text = _text()
    references = (ROOT / "paper/references.md").read_text(encoding="utf-8")
    pattern = re.compile(r"\[RELATED: ([a-z0-9-; ]+)\]")

    used = {a.strip() for group in pattern.findall(text) for a in group.split(";")}
    available = {
        a.strip() for group in pattern.findall(references) for a in group.split(";")
    }
    assert used, "draft should cite at least one related-work anchor"
    assert used <= available


def test_draft_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"
