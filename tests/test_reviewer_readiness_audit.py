"""Checks for docs/REVIEWER_READINESS_AUDIT.md: it exists, is indexed, covers
all six audit dimensions, resolves its referenced artifacts, and records that
the draft is free of unresolved placeholders (the audit's own claim that the
draft is production-clean must stay true).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "docs/REVIEWER_READINESS_AUDIT.md"
DRAFT_PATH = ROOT / "paper/draft_v0.md"

REQUIRED_SECTION_HEADINGS = [
    "## 1. Claim consistency",
    "## 2. Evidence traceability",
    "## 3. Table / readability audit",
    "## 4. Methodological attack surface",
    "## 5. Submission-readiness checklist",
    "## 6. Recommended next PR",
]

# The eight reviewer attacks the audit must explicitly address.
REQUIRED_ATTACK_KEYWORDS = [
    "candidate-identity",
    "semantic under a directional task",
    "internal-mechanism proof",
    "functional form",
    "crossvul accuracy is confounded",
    "human adjudication set is small",
    "structural, not learned",
    "failed transfer",
]


def _normalized(text: str) -> str:
    return " ".join(text.split()).lower()


def test_audit_exists_and_is_indexed():
    assert AUDIT_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/REVIEWER_READINESS_AUDIT.md" in readme
    assert "docs/REVIEWER_READINESS_AUDIT.md" in index


def test_audit_covers_all_six_dimensions():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    for heading in REQUIRED_SECTION_HEADINGS:
        assert heading in text, heading


def test_audit_addresses_all_eight_attacks():
    normalized = _normalized(AUDIT_PATH.read_text(encoding="utf-8"))
    for keyword in REQUIRED_ATTACK_KEYWORDS:
        assert keyword.lower() in normalized, keyword


def test_audit_states_a_verdict_and_one_recommended_next_pr():
    normalized = _normalized(AUDIT_PATH.read_text(encoding="utf-8"))
    assert "verdict:" in normalized
    assert "recommendation: b" in normalized
    assert "add mechanism and repair figures" in normalized


def test_audit_referenced_paths_resolve():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    dir_pat = re.compile(
        r"`((?:reports|docs|paper|src|scripts|reproducibility)/[A-Za-z0-9_./-]+\.(?:md|json|py))`"
    )
    for rel in set(dir_pat.findall(text)):
        assert (ROOT / rel).exists(), rel
    # bare *_v1.json artifact references resolve under reports/
    for name in set(re.findall(r"`([a-z0-9_]+_v1\.json)`", text)):
        assert (ROOT / "reports" / name).exists(), name


def test_draft_remains_placeholder_and_todo_free():
    # The audit asserts the draft is production-clean; keep that true.
    draft = DRAFT_PATH.read_text(encoding="utf-8")
    assert "APPENDIX PLACEHOLDER" not in draft
    assert "TODO" not in draft


def test_draft_anchor_map_still_resolves():
    # Guard the audit's evidence-traceability claim: draft anchors == map anchors.
    draft = DRAFT_PATH.read_text(encoding="utf-8")
    anchor_map = (ROOT / "paper/result_anchor_map.md").read_text(encoding="utf-8")
    pattern = re.compile(r"\[RESULT: [a-z0-9-]+\]")
    assert set(pattern.findall(draft)) == set(pattern.findall(anchor_map))
