"""Guards that paper/draft_v0.md stays aligned with the finalized evidence
boundaries (candidate-identity task, CodeBERT/Qwen functional-form caveat,
CrossVul confound caveat, structural-vs-learned repair distinction) and does
not drift into bare overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = ROOT / "paper/draft_v0.md"

FORBIDDEN_PHRASES = [
    "we solve repair",
    "repair works",
    "we prove internal mechanism",
    "universal model failure",
    "model now reasons correctly",
    "crossvul proves generalization",
    "secure patch reasoning is solved",
]


def _normalized(text: str) -> str:
    no_quote_markers = re.sub(r"(?m)^\s*>\s?", "", text)
    return " ".join(no_quote_markers.split()).lower()


def _strip_quoted_spans(text: str) -> str:
    return re.sub(r'"[^"]*"', "", text)


def test_draft_states_candidate_identity_task_boundary():
    text = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    assert "candidate-identity" in text
    assert "directional-patch" in text
    assert "nuisance variable" in text


def test_draft_states_functional_form_difference_in_main_text():
    draft = DRAFT_PATH.read_text(encoding="utf-8")
    # The caveat must live in a mechanism section (6.x), not only limitations.
    mechanism = draft.split("## 7.")[0]
    normalized = _normalized(mechanism)
    assert "functional form" in normalized
    assert "crude net-polarity" in normalized or "crude polarity" in normalized
    assert "shared internal mechanism" in normalized


def test_draft_states_crossvul_confound_caveat():
    text = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    assert "should therefore not be read as stronger secure-code reasoning" in text or (
        "not standalone evidence of stronger" in text
    )
    assert "stronger presentation shortcut" in text or "presentation-correlated shortcut" in text


def test_draft_distinguishes_structural_from_learned_repair():
    text = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    assert "antisymmetric readout" in text
    assert "structural consistency constraint" in text
    assert "not" in text and "validated learned repair" in text


def test_draft_thesis_present():
    text = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    assert "pointwise secure-code accuracy can hide relation-violating behavior" in text


def test_draft_has_no_bare_overclaims():
    unquoted = _strip_quoted_spans(DRAFT_PATH.read_text(encoding="utf-8")).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in unquoted, f"found bare overclaim '{phrase}'"


def test_draft_contribution_list_is_evidence_aligned():
    text = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    assert "five bounded" in text
    assert "structural antisymmetric readout control" in text
    assert "competency-matched non-qwen behavioral replication" in text
