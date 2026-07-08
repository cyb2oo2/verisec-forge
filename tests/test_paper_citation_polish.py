"""Checks for the external-review polish pass and the follow-up citation-gap
resolution pass: the title no longer uses the flagged "reasoning" wording,
every previously-listed citation gap now has a verified (not fabricated)
reference entry, and the external feedback packet reflects the current draft
state.
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


def test_citation_gaps_are_resolved_not_fabricated():
    # The "Citation Gaps" section (added in the earlier polish pass) has been
    # removed now that every previously-listed source has a verified entry.
    assert "## Citation Gaps" not in REFERENCES
    assert "citation needed" not in REFERENCES.lower()
    normalized = " ".join(REFERENCES.split()).lower()
    assert "no citation gaps remain" in normalized


def test_previously_gapped_sources_have_verified_identifiers():
    # Pin the exact, independently-verified identifiers for each source that
    # was previously a bare "citation needed" placeholder, so a future edit
    # can't silently regress one back into an unverified or fabricated entry.
    expected = {
        "crossvul": "10.1145/3468264.3473122",
        "patcheval": "2511.11019",
        "qwen25-coder": "2409.12186",
        "qwen25": "2412.15115",
        "distilgpt2": "1910.01108",
        "deltasecommits": "huggingface.co/datasets/rufimelo/DeltaSecommits",
    }
    for anchor, identifier in expected.items():
        entry_pat = re.compile(rf"\[RELATED: {re.escape(anchor)}\][^\[]*")
        match = entry_pat.search(REFERENCES)
        assert match, f"no reference entry for [RELATED: {anchor}]"
        assert identifier in match.group(0), (anchor, identifier)


def test_deltasecommits_paper_uncertainty_is_disclosed_not_hidden():
    # The DeltaSecommits dataset is verified, but its associated paper's full
    # author list and DOI/arXiv id are not -- that limitation must stay
    # explicit rather than being papered over with an invented citation.
    normalized = " ".join(REFERENCES.split()).lower()
    assert "could not be independently verified" in normalized


def test_uncited_sources_named_in_draft_are_covered_by_references():
    # Any dataset/model named in the draft has a verified reference entry --
    # never silently uncited.
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
