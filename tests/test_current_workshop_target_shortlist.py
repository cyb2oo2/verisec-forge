"""Checks for docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md: the shortlist
exists, covers all 5 required candidate categories, is framed as a snapshot
requiring re-verification, uses the closed/unclear/unverified honesty
convention rather than inventing details, names exactly one top-3 list and
one first-preparation target, and avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHORTLIST_PATH = ROOT / "docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md"

REQUIRED_CATEGORY_HEADINGS = [
    "## AI for Code / Code Generation Workshops",
    "## Security / Vulnerability Analysis Workshops",
    "## LLM Evaluation Workshops",
    "## Trustworthy ML / AI Safety Evaluation Workshops",
    "## Empirical Software Engineering / Software Mining Venues",
]

REQUIRED_CLOSING_HEADINGS = [
    "## 1. Top 3 Realistic Targets",
    "## 2. Which One to Prepare for First",
    "## 3. Preprint Timing Relative to Submission",
    "## 4. Whether the Paper Needs Compression Before Submission",
    "## 5. Recommended Next PR After This Shortlist",
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
    return SHORTLIST_PATH.read_text(encoding="utf-8")


def test_shortlist_exists_and_is_nonempty() -> None:
    assert SHORTLIST_PATH.exists()
    assert _text().strip()


def test_shortlist_is_indexed() -> None:
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md" in index


def test_shortlist_covers_all_required_categories() -> None:
    text = _text()
    for heading in REQUIRED_CATEGORY_HEADINGS:
        assert heading in text, heading


def test_shortlist_has_all_closing_sections() -> None:
    text = _text()
    for heading in REQUIRED_CLOSING_HEADINGS:
        assert heading in text, heading


def test_shortlist_is_framed_as_a_snapshot() -> None:
    normalized = _text().lower()
    assert "snapshot, not a standing fact" in normalized
    assert "re-check" in normalized or "re-verify" in normalized


def test_shortlist_uses_honesty_markers_not_invented_details() -> None:
    text = _text()
    # The doc must actually use all three honesty markers somewhere -- a
    # shortlist with zero "unverified"/"unclear" entries across 14 real
    # candidates would itself be a signal something was invented rather than
    # checked.
    assert "**Closed**" in text or "Closed" in text
    assert "**Unverified**" in text or "unverified" in text.lower()
    assert "unclear" in text.lower()


def test_shortlist_names_exactly_three_top_targets() -> None:
    section = _text().split("## 1. Top 3 Realistic Targets")[1].split("## 2.")[0]
    numbered_items = re.findall(r"^\d+\.\s+\*\*", section, flags=re.MULTILINE)
    assert len(numbered_items) == 3, numbered_items


def test_shortlist_chooses_one_venue_to_prepare_first() -> None:
    section = _text().split("## 2. Which One to Prepare for First")[1].split(
        "## 3."
    )[0]
    assert section.strip().startswith("**")


def test_shortlist_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"


def test_shortlist_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    shortlist_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert shortlist_anchors <= draft_anchors


def test_shortlist_referenced_paths_resolve() -> None:
    text = _text()
    dir_pattern = re.compile(
        r"`((?:reports|docs|paper|src|scripts|reproducibility|tests)/"
        r"[A-Za-z0-9_./-]+\.(?:md|json|py|svg))`"
    )
    referenced = {m.split("::")[0] for m in dir_pattern.findall(text)}
    assert referenced, "shortlist should reference the prior targeting plan"
    for relative_path in referenced:
        assert (ROOT / relative_path).exists(), relative_path
