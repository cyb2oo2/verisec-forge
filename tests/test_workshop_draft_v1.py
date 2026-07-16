"""Checks for paper/workshop_draft_v1.md: the revised draft exists, keeps
all required sections, has a 150-180 word abstract, and implements the six
readiness-audit-driven revisions (concrete candidate-identity example,
related-work positioning sentence, reduced CrossVul body table,
prompt-sensitivity rebuttal, repair bridge sentence, SaTML/trustworthy-ML
framing), while all anchors resolve correctly, no new [RESULT: ...]
anchors were added, no forbidden overclaims appear, and the SaTML 2027
re-check caveat remains.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = ROOT / "paper/workshop_draft_v1.md"

REQUIRED_SECTIONS = [
    "## 1. Introduction",
    "## 2. Task Formulation",
    "## 3. VeriPatch-RR Evaluation Design",
    "## 4. Label-vs-Polarity Findings",
    "## 5. Cross-Source and Cross-Architecture Checks",
    "## 6. Repair Decomposition",
    "## 7. Limitations and Responsible Use",
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


def test_draft_v1_exists_and_is_nonempty() -> None:
    assert DRAFT_PATH.exists()
    assert _text().strip()


def test_draft_v1_has_all_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_draft_v1_title_keeps_relational_consistency() -> None:
    first_line = _text().splitlines()[0]
    assert "Relational Consistency" in first_line
    assert "Relational Reasoning" not in first_line


def test_abstract_word_count_within_target() -> None:
    text = _text()
    match = re.search(
        r"## Abstract.*?\n\n(.*?)\n\n## 1\. Introduction", text, flags=re.DOTALL
    )
    assert match, "could not locate abstract block"
    words = match.group(1).split()
    assert 150 <= len(words) <= 180, len(words)


def test_candidate_identity_concrete_example_exists() -> None:
    section = _text().split("## 2. Task Formulation")[1].split("## 3.")[0]
    normalized = section.lower()
    assert "concretely" in normalized or "for example" in normalized
    assert "buffer-overflow" in normalized or "vulnerable function" in normalized


def test_related_work_positioning_sentence_exists() -> None:
    section = _text().split("## 1. Introduction")[1].split("## 2.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "differs from prior vulnerability benchmarks" in normalized
    assert "counterfactual" in normalized


def test_reduced_crossvul_body_table_exists() -> None:
    section = _text().split("## 5. Cross-Source")[1].split("## 6.")[0]
    assert "| Metric | PrimeVul | CrossVul |" in section
    assert "0.706" in section and "0.855" in section
    assert "~0.57" in section and "~0.92" in section
    assert "~0.96" in section and "~0.93" in section
    assert "not a new result" in section.lower()


def test_prompt_sensitivity_rebuttal_exists() -> None:
    section = _text().split("## 4. Label-vs-Polarity Findings")[1].split("## 5.")[0]
    assert "not generic prompt sensitivity" in section.lower()


def test_repair_bridge_sentence_exists() -> None:
    section = _text().split("## 6. Repair Decomposition")[1].split("## 7.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert normalized.strip().startswith("having isolated a presentation-structure failure")


def test_satml_trustworthy_ml_framing_exists() -> None:
    normalized = _text().lower()
    assert "trustworthy-ml evaluation" in normalized


def test_satml_2027_recheck_caveat_remains() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "satml 2027" in normalized
    assert "not yet published" in normalized
    assert "re-check" in normalized


def test_all_result_anchors_resolve_and_none_are_new() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    map_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/result_anchor_map.md").read_text(encoding="utf-8"),
        )
    )
    used = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert used, "draft should cite existing result anchors"
    assert used <= draft_anchors
    assert used <= map_anchors


def test_all_related_anchors_resolve() -> None:
    text = _text()
    references = (ROOT / "paper/references.md").read_text(encoding="utf-8")
    pattern = re.compile(r"\[RELATED: ([a-z0-9-; ]+)\]")
    used = {a.strip() for group in pattern.findall(text) for a in group.split(";")}
    available = {
        a.strip() for group in pattern.findall(references) for a in group.split(";")
    }
    assert used, "draft should cite at least one related-work anchor"
    assert used <= available


def test_draft_v1_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"
