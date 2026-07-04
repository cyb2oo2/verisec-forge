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


def test_draft_has_no_appendix_placeholders():
    text = DRAFT_PATH.read_text(encoding="utf-8")
    assert "APPENDIX PLACEHOLDER" not in text


def test_draft_section_numbering_is_coherent():
    text = DRAFT_PATH.read_text(encoding="utf-8")
    numbers = [int(m) for m in re.findall(r"(?m)^## (\d+)\.", text)]
    assert numbers == list(range(1, 11)), numbers  # sections 1..10, no gaps/dupes


def test_draft_has_the_three_production_tables_with_caveats():
    text = DRAFT_PATH.read_text(encoding="utf-8")
    normalized = _normalized(text)
    # Table presence
    assert "table 2. label-vs-polarity mechanism decomposition" in normalized
    assert "table 3. polarity/gold presentation confound" in normalized
    assert "table 4. repair decomposition" in normalized
    # Required caveats attached to each table
    assert "does not establish a shared internal mechanism" in normalized
    assert "not be treated as standalone evidence of stronger reasoning" in normalized
    assert "antisymmetric consistency is by construction" in normalized


def test_appendix_referenced_paths_resolve():
    text = DRAFT_PATH.read_text(encoding="utf-8")
    pattern = re.compile(
        r"`((?:reports|docs|src|scripts|reproducibility)/[A-Za-z0-9_./-]+\.(?:md|json|py))`"
    )
    for rel in set(pattern.findall(text)):
        assert (ROOT / rel).exists(), rel
