"""Checks for docs/PAPER_READINESS_AUDIT.md: it is indexed, its references
resolve, it covers every required paper section, it carries the reusable
claim-boundary paragraph, and it does not introduce bare overclaim language
while auditing readiness.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "docs/PAPER_READINESS_AUDIT.md"

FORBIDDEN_PHRASES = [
    "all models",
    "universal mechanism",
    "internal mechanism proven",
    "repair works",
    "model now reasons correctly",
    "crossvul proves generalization",
]

REQUIRED_SECTION_HEADINGS = [
    "## 1. Main thesis readiness",
    "## 2. Mechanism claim readiness",
    "## 3. Cross-source / CrossVul readiness",
    "## 4. Repair section readiness",
    "## 5. Human adjudication readiness",
    "## 6. Optional experiments remaining",
    "## 7. Proposed paper claim boundary",
    "## 8. Recommended next step",
]

# Required claim-boundary substrings (normalized whitespace, lowercased).
REQUIRED_CLAIM_BOUNDARY_PHRASES = [
    "candidate-identity",
    "pointwise",
    "diff-hunk polarity",
    "replicates across two competency-matched architectures",
    "structural constraint for side-order consistency",
    "learned",
    "no internal-mechanistic",
]


def _strip_quoted_spans(text: str) -> str:
    return re.sub(r'"[^"]*"', "", text)


def _normalized(text: str) -> str:
    # Drop markdown blockquote markers so wrapped quoted lines read as prose.
    no_quote_markers = re.sub(r"(?m)^\s*>\s?", "", text)
    return " ".join(no_quote_markers.split()).lower()


def test_audit_exists_and_is_indexed():
    assert AUDIT_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/PAPER_READINESS_AUDIT.md" in readme
    assert "docs/PAPER_READINESS_AUDIT.md" in index


def test_audit_covers_all_eight_sections():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    for heading in REQUIRED_SECTION_HEADINGS:
        assert heading in text, heading


def test_reusable_claim_boundary_paragraph_present():
    normalized = _normalized(AUDIT_PATH.read_text(encoding="utf-8"))
    for phrase in REQUIRED_CLAIM_BOUNDARY_PHRASES:
        assert phrase.lower() in normalized, phrase


def test_no_bare_overclaim_phrases():
    unquoted = _strip_quoted_spans(AUDIT_PATH.read_text(encoding="utf-8")).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in unquoted, f"found unquoted overclaim '{phrase}'"


def test_recommends_paper_draft_alignment():
    normalized = " ".join(AUDIT_PATH.read_text(encoding="utf-8").split()).lower()
    assert "recommendation: a (paper draft alignment)" in normalized


def test_optional_items_do_not_block_draft():
    normalized = " ".join(AUDIT_PATH.read_text(encoding="utf-8").split()).lower()
    assert "none blocks a first serious paper draft" in normalized


def test_referenced_paths_resolve():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    # dir-prefixed references
    dir_pat = re.compile(r"`((?:reports|docs|paper|src|scripts)/[A-Za-z0-9_./-]+\.(?:md|json|py))`")
    for rel in set(dir_pat.findall(text)):
        assert (ROOT / rel).exists(), rel
    # bare report filenames (resolve under reports/)
    bare_pat = re.compile(r"`([A-Z][A-Z0-9_]+\.md)`")
    for name in set(bare_pat.findall(text)):
        assert (ROOT / "reports" / name).exists(), name
