"""Checks for docs/EXPERIMENT_COMPLETENESS_AUDIT.md: it is indexed, its
resolvable references exist, it covers every required claim, and it does not
introduce a bare "repair works" / "learned repair validated" claim while
discussing the (deliberately unresolved) repair line.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "docs/EXPERIMENT_COMPLETENESS_AUDIT.md"

FORBIDDEN_PHRASES = [
    "repair works",
    "learned repair validated",
    "model now reasons correctly",
    "fine-tuning generalizes",
]

REQUIRED_CLAIM_HEADINGS = [
    "## A. Relational evaluation contribution",
    "## B. Mechanism claim",
    "## C. Task formulation claim",
    "## D. Repair contribution",
    "## E. Cross-source / external validity",
    "## F. Human adjudication / evidence localization",
]

REQUIRED_PER_CLAIM_FIELDS = [
    "**Claim.**",
    "**Current evidence.**",
    "**Current weakness.**",
    "**Likely reviewer attack.**",
    "**Required next experiment or control.**",
    "**Priority.**",
    "**Decision.**",
]


def _strip_quoted_spans(text: str) -> str:
    return re.sub(r'"[^"]*"', "", text)


def test_audit_document_exists_and_is_indexed():
    assert AUDIT_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    results_index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/EXPERIMENT_COMPLETENESS_AUDIT.md" in readme
    assert "docs/EXPERIMENT_COMPLETENESS_AUDIT.md" in results_index


def test_audit_covers_all_six_claims_with_required_fields():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    for heading in REQUIRED_CLAIM_HEADINGS:
        assert heading in text, heading
    # Check the required fields appear at least once per claim section by
    # splitting on the claim headings and checking each section.
    sections = re.split(r"\n## [A-F]\. ", text)[1:]
    assert len(sections) == len(REQUIRED_CLAIM_HEADINGS)
    for section in sections:
        for field in REQUIRED_PER_CLAIM_FIELDS:
            assert field in section, (section[:60], field)


def test_audit_has_priority_summary_and_recommendation():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    assert "## Recommendation" in text
    assert "## Priority summary" in text
    normalized = " ".join(text.split()).lower()
    assert (
        "crossvul confound measurement) is the more urgent next pr" in normalized
    )


def test_audit_referenced_report_and_doc_paths_resolve():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    pattern = re.compile(r"`((?:reports|docs)/[A-Za-z0-9_./-]+\.(?:md|json))`")
    referenced = set(pattern.findall(text))
    assert referenced, "audit should cite concrete report/doc artifacts"
    for relative_path in referenced:
        assert (ROOT / relative_path).exists(), relative_path


def test_audit_does_not_contain_bare_forbidden_repair_claims():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    unquoted = _strip_quoted_spans(text).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in unquoted, f"found unquoted '{phrase}' in audit doc"


def test_audit_keeps_repair_v1_closed():
    text = AUDIT_PATH.read_text(encoding="utf-8")
    normalized = " ".join(text.split()).lower()
    assert "do not pursue now" in normalized
    assert "keep repair v1 closed" in normalized
    assert "do not restart fine-tuning" in normalized
