"""Checks for the external-review polish pass: the title no longer uses the
flagged "reasoning" wording, citation gaps are explicitly listed (not
fabricated), and the external feedback packet reflects the current draft state.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT = (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8")
REFERENCES = (ROOT / "paper/references.md").read_text(encoding="utf-8")
OUTLINE = (ROOT / "paper/outline.md").read_text(encoding="utf-8")
FIGURE1 = (ROOT / "paper/figures/figure1_problem.svg").read_text(encoding="utf-8")
PACKET = (ROOT / "docs/EXTERNAL_FEEDBACK_PACKET.md").read_text(encoding="utf-8")


def test_title_uses_consistency_not_reasoning_everywhere():
    # Draft H1
    h1 = DRAFT.splitlines()[0]
    assert h1.startswith("# ")
    assert "Relational Consistency" in h1
    assert "Relational Reasoning" not in h1
    # Figure 1 visible title matches
    assert "Pointwise Accuracy Is Not Relational Consistency" in FIGURE1
    assert "Relational Reasoning" not in FIGURE1
    # Outline working title: the bold title line itself, not the note that
    # explains the change (which legitimately quotes the old wording).
    title_line = next(
        line for line in OUTLINE.splitlines() if line.startswith("**Pointwise")
    )
    assert "Relational Consistency" in title_line
    assert "Relational Reasoning" not in title_line


def test_citation_gaps_section_lists_uncited_sources_without_fabrication():
    assert "## Citation Gaps" in REFERENCES
    gaps = REFERENCES.split("## Citation Gaps")[1].lower()
    for source in ["crossvul", "deltasecommits", "patcheval", "qwen2.5-coder", "distilgpt2"]:
        assert source in gaps, source
    # Each gap is explicitly marked, not fabricated with a fake arXiv id.
    assert "citation needed" in gaps


def test_uncited_sources_named_in_draft_are_covered_by_gaps_or_references():
    # Any dataset/model used in the draft is either in a verified reference or
    # explicitly listed as a citation gap -- never silently uncited.
    refs_lower = REFERENCES.lower()
    for source in ["crossvul", "deltasecommits", "patcheval", "distilgpt2"]:
        if source in DRAFT.lower():
            assert source in refs_lower, source


def test_related_anchors_still_subset_of_references():
    anchor_pat = re.compile(r"\[RELATED: ([a-z0-9-; ]+)\]")
    draft_anchors = {
        a.strip() for grp in anchor_pat.findall(DRAFT) for a in grp.split(";")
    }
    ref_anchors = {
        a.strip() for grp in anchor_pat.findall(REFERENCES) for a in grp.split(";")
    }
    assert draft_anchors
    assert draft_anchors <= ref_anchors


def test_external_packet_reflects_current_draft_state():
    normalized = " ".join(PACKET.split()).lower()
    assert "tables 2" in normalized  # tables 2-4 mentioned
    assert "figures 5" in normalized  # figures 5-7 mentioned
    assert "no must-run experiment is pending" in normalized
    assert "citation gaps" in normalized
    # Must not overstate as final submission.
    assert "working draft, not a final submission" in normalized


def test_abstract_names_candidate_identity_boundary():
    abstract = DRAFT.split("## 1.")[0].lower()
    assert "candidate-identity" in abstract
