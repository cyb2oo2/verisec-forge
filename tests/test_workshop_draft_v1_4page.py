"""Checks for paper/workshop_draft_v1_4page.md: Path-C1 hard-4-page cut.

Keeps claim integrity (tables 2/4, functional form, confound, structural vs
learned repair, CI-vs-release repro) while dropping body figures and
compressing prose. No new [RESULT: ...] anchors.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = ROOT / "paper/workshop_draft_v1_4page.md"

REQUIRED_SECTIONS = [
    "## Abstract",
    "## 1. Introduction, Task, and Instrument",
    "## 2. Label-vs-Polarity Findings",
    "## 3. Cross-Source Confound",
    "## 4. Repair Decomposition",
    "## 5. Limitations, Responsible Use, and Artifacts",
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


def test_4page_draft_exists() -> None:
    assert DRAFT_PATH.exists()
    assert _text().strip()


def test_4page_has_required_sections() -> None:
    text = _text()
    for heading in REQUIRED_SECTIONS:
        assert heading in text, heading


def test_4page_no_body_figures_or_placeholders() -> None:
    text = _text()
    assert not re.search(r"\[Figure \d+ here\]", text)
    assert not re.search(r"\[Table \d+ here\]", text)
    # Path C1: no embedded figure images in the 4-page body
    assert not re.search(r"!\[[^\]]*\]\(figures/", text)


def test_4page_keeps_tables_2_and_4() -> None:
    text = _text()
    assert "**Table 2." in text
    assert "**Table 4." in text
    assert "| Metric | Qwen | CodeBERT |" in text
    assert "0.660" in text and "0.733" in text


def test_4page_functional_form_and_confound() -> None:
    text = _text()
    assert "functional form" in text.lower()
    assert "~0.57" in text and "~0.96" in text
    assert "0.706" in text and "0.855" in text
    assert "not standalone evidence" in text.lower() or "not standalone" in text.lower()


def test_4page_structural_vs_learned_repair() -> None:
    text = _text().lower()
    assert "antisymmetric" in text
    assert "p=0.002" in text or "p = 0.002" in text
    assert "0.508" in text
    assert "left unresolved" in text or "leave learned repair unresolved" in text


def test_4page_ci_vs_release_repro() -> None:
    section = _text().split("## 5.")[1]
    normalized = section.lower()
    assert "ci smoke" in normalized or "ci" in normalized
    assert "30-pair" in normalized or "30 pair" in normalized
    assert "release" in normalized
    assert "does **not** train" in section.lower() or "does not train" in normalized


def test_4page_body_word_budget() -> None:
    text = _text()
    start = text.find("## Abstract")
    end = text.find("## Supplement Note")
    assert start >= 0 and end > start
    body = text[start:end]
    words = len(
        re.sub(
            r"\[RESULT: [a-z0-9-]+\]|\[RELATED: [a-z0-9-; ]+\]|`|\*|#",
            "",
            body,
        ).split()
    )
    # Path C1 target ~1050-1200; allow a small band for edits.
    assert 900 <= words <= 1400, words


def test_4page_anchors_resolve_and_none_are_new() -> None:
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
    assert used
    assert used <= draft_anchors
    assert used <= map_anchors


def test_4page_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, phrase


def test_4page_title_keeps_relational_consistency() -> None:
    first = _text().splitlines()[0]
    assert "Relational Consistency" in first
    assert "Relational Reasoning" not in first
