"""Checks for the metadata / responsible-use / AI-disclosure PR:
CITATION.cff no longer carries a placeholder-only author, the paper states
a responsible-use paragraph, the paper still states its deployed-scanner
and candidate-identity boundaries, docs/AI_USE_DISCLOSURE_DRAFT.md exists
and is honest about AI use, no forbidden overclaims appear in the new
material, and no new [RESULT: ...] anchors were introduced.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CITATION_PATH = ROOT / "CITATION.cff"
DRAFT_PATH = ROOT / "paper/draft_v0.md"
DISCLOSURE_PATH = ROOT / "docs/AI_USE_DISCLOSURE_DRAFT.md"

FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]

PLACEHOLDER_AUTHOR_STRINGS = [
    "VeriSec Forge contributors",
]


def test_citation_cff_no_longer_has_placeholder_author() -> None:
    text = CITATION_PATH.read_text(encoding="utf-8")
    for placeholder in PLACEHOLDER_AUTHOR_STRINGS:
        assert placeholder not in text, placeholder
    assert "authors:" in text
    # Some real identifier must be present in the authors block, not an
    # empty or purely structural entry.
    authors_block = text.split("authors:", 1)[1].split("\n\n", 1)[0]
    assert re.search(r"(name|alias|given-names|family-names):\s*\S", authors_block)


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_paper_states_responsible_use_paragraph() -> None:
    text = DRAFT_PATH.read_text(encoding="utf-8")
    assert "Responsible use" in text
    normalized = _normalized_whitespace(text).lower()
    assert "does not replace human security review" in normalized
    assert "false reassurance" in normalized
    assert "deployment-facing use" in normalized


def test_paper_still_states_not_a_deployed_scanner() -> None:
    normalized = _normalized_whitespace(DRAFT_PATH.read_text(encoding="utf-8")).lower()
    assert "not a deployed vulnerability scanner" in normalized


def test_paper_still_distinguishes_candidate_identity_from_directional() -> None:
    normalized = DRAFT_PATH.read_text(encoding="utf-8").lower()
    assert "candidate-identity" in normalized
    assert "directional" in normalized


def test_ai_use_disclosure_draft_exists() -> None:
    assert DISCLOSURE_PATH.exists()
    assert DISCLOSURE_PATH.read_text(encoding="utf-8").strip()


def test_ai_use_disclosure_distinguishes_required_categories() -> None:
    text = DISCLOSURE_PATH.read_text(encoding="utf-8")
    for category in [
        "Research code / experiment execution",
        "Writing assistance",
        "Editing / planning assistance",
        "Human responsibility for claims, citations, and final text",
    ]:
        assert category in text, category


def test_ai_use_disclosure_does_not_claim_no_ai_tools_were_used() -> None:
    # The document must contain the correct *negated* form (explicitly
    # denying the "no AI tools were used" claim), and must never assert
    # that bare claim as true anywhere outside of that negation.
    normalized = _normalized_whitespace(DISCLOSURE_PATH.read_text(encoding="utf-8")).lower()
    assert "does not claim that no ai tools were used" in normalized

    bare_claim = "no ai tools were used"
    idx = normalized.find(bare_claim)
    assert idx != -1, "expected the negated phrasing to be present"
    # Every occurrence of the bare claim must be immediately preceded by a
    # negation cue ("claim that no ai tools were used" / "not... no ai
    # tools were used"), never asserted standalone as true.
    pos = 0
    while True:
        idx = normalized.find(bare_claim, pos)
        if idx == -1:
            break
        preceding = normalized[max(0, idx - 20) : idx]
        assert "claim that" in preceding or "not" in preceding, preceding
        pos = idx + 1


def test_no_forbidden_overclaims_in_new_material() -> None:
    for path in (DISCLOSURE_PATH,):
        normalized = path.read_text(encoding="utf-8").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in normalized, f"{path}: found forbidden phrase {phrase!r}"

    # The paper draft is not held to the same bare-substring standard as
    # planning docs (it legitimately quotes these phrases inside its own
    # negated disclaimer sentences), so only the newly added paragraph is
    # checked here rather than the whole file.
    text = DRAFT_PATH.read_text(encoding="utf-8")
    start = text.find("**Responsible use.**")
    end = text.find("The benchmark relies on existing")
    assert start != -1 and end != -1
    new_paragraph = text[start:end].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in new_paragraph, f"new paragraph: found forbidden phrase {phrase!r}"


def test_no_new_result_anchors_added() -> None:
    draft_text = DRAFT_PATH.read_text(encoding="utf-8")
    anchor_map_text = (ROOT / "paper/result_anchor_map.md").read_text(encoding="utf-8")
    pattern = re.compile(r"\[RESULT: [a-z0-9-]+\]")

    draft_anchors = set(pattern.findall(draft_text))
    mapped_anchors = set(pattern.findall(anchor_map_text))
    assert draft_anchors == mapped_anchors

    disclosure_anchors = set(pattern.findall(DISCLOSURE_PATH.read_text(encoding="utf-8")))
    assert not disclosure_anchors
