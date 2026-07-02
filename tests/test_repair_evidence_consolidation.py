"""Claim-boundary checks for the repair evidence consolidation (closes the v1
antisymmetric-repair line after #54/#55): the antisymmetric readout is a
validated, transferable structural fix; the fine-tuning objective on top of it
is not validated as a transferable learned repair. These checks guard against
that boundary drifting back toward an overclaim in any of the consolidated
docs.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PHRASES = [
    "repair works",
    "learned repair validated",
    "model now reasons correctly",
    "fine-tuning generalizes",
]

CONSOLIDATED_DOCS = [
    ROOT / "README.md",
    ROOT / "docs/EVIDENCE_HIERARCHY.md",
    ROOT / "docs/REPAIR_OBJECTIVE_DESIGN.md",
    ROOT / "docs/REPAIR_EXPERIMENT_PREREGISTRATION.md",
    ROOT / "paper/outline.md",
    ROOT / "reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md",
    ROOT / "reports/RESULTS_INDEX.md",
]


def _strip_quoted_spans(text: str) -> str:
    # Explicitly quoted mentions (e.g. `"repair works"` inside a sentence that
    # disclaims the phrase, as in "Does not establish ... 'repair works'
    # claim") are legitimate; only a bare, unquoted assertion is a violation.
    return re.sub(r'"[^"]*"', "", text)


def test_no_bare_forbidden_repair_claims_in_consolidated_docs():
    for path in CONSOLIDATED_DOCS:
        assert path.exists(), path
        text = path.read_text(encoding="utf-8")
        unquoted = _strip_quoted_spans(text).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in unquoted, f"{path}: found unquoted '{phrase}'"


def test_evidence_hierarchy_classifies_antisymmetric_readout_and_fine_tuning():
    doc = (ROOT / "docs/EVIDENCE_HIERARCHY.md").read_text(encoding="utf-8")
    assert "#54" in doc and "#55" in doc
    assert "structural control" in doc.lower() or "structural fix" in doc.lower()
    assert "not validated" in doc.lower()
    normalized = " ".join(doc.split())
    assert (
        "transferable structural constraint for side-order consistency" in normalized
    )
    assert "does not survive external-source or nuisance-transform transfer" in normalized


def test_repair_objective_design_has_v1_outcome_section():
    doc = (ROOT / "docs/REPAIR_OBJECTIVE_DESIGN.md").read_text(encoding="utf-8")
    assert "## v1 outcome" in doc.lower() or "v1 outcome" in doc
    normalized = " ".join(doc.split()).lower()
    assert "works by construction" in normalized
    assert "transfers" in normalized
    assert "does not transfer robustly" in normalized


def test_paper_outline_retains_hard_antisymmetric_readout_contribution():
    outline = (ROOT / "paper/outline.md").read_text(encoding="utf-8")
    normalized = " ".join(outline.split())
    assert (
        "hard antisymmetric readout as a transferable structural consistency "
        "constraint" in normalized.lower()
    )
    assert "future work" in normalized.lower()
    assert "not another readout tweak" in normalized.lower()


def test_readme_headline_uses_preferred_repair_wording():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        "Antisymmetric readout transfers as a structural fix; the current "
        "fine-tuning objective does not validate as transferable learned "
        "repair" in readme
    )


def test_results_index_titles_distinguish_attempt_and_transfer_boundary():
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "#54" in index and "#55" in index
    assert "Repair Attempt:" in index
    assert "Repair Transfer Boundary:" in index


def test_consolidated_docs_reference_paths_resolve():
    pattern = re.compile(r"`((?:reports|docs|paper)/[A-Za-z0-9_./-]+\.(?:md|json))`")
    for path in CONSOLIDATED_DOCS:
        text = path.read_text(encoding="utf-8")
        for relative_path in pattern.findall(text):
            assert (ROOT / relative_path).exists(), (path, relative_path)
