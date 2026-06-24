from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_paper_draft_packet_exists() -> None:
    expected = [
        "paper/README.md",
        "paper/abstract.md",
        "paper/outline.md",
        "paper/main_claims.md",
        "paper/draft_v0.md",
        "paper/result_anchor_map.md",
        "paper/references.md",
        "paper/tables/main_results.md",
        "paper/figures/figure1_problem.svg",
        "paper/figures/figure2_veripatch_rr.svg",
        "paper/figures/figure3_mechanism_decomposition.svg",
        "paper/figures/figure4_discovery_confirmation.svg",
    ]

    for relative_path in expected:
        path = ROOT / relative_path
        assert path.exists(), relative_path
        assert path.read_text(encoding="utf-8").strip(), relative_path


def test_paper_claim_boundary_keeps_readout_frozen() -> None:
    claims = (ROOT / "paper/main_claims.md").read_text(encoding="utf-8")
    outline = (ROOT / "paper/outline.md").read_text(encoding="utf-8")

    assert "Side-order reasoning remains unresolved" in claims
    assert "not about a promoted high-accuracy model" in claims
    assert "another readout tweak" in outline


def test_paper_figures_are_svg_documents() -> None:
    for path in (ROOT / "paper/figures").glob("figure*.svg"):
        text = path.read_text(encoding="utf-8")
        assert text.startswith("<svg"), path.name
        assert "</svg>" in text, path.name


def test_paper_result_anchors_have_report_map() -> None:
    draft = (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8")
    anchor_map = (ROOT / "paper/result_anchor_map.md").read_text(
        encoding="utf-8"
    )
    pattern = re.compile(r"\[RESULT: [a-z0-9-]+\]")

    draft_anchors = set(pattern.findall(draft))
    mapped_anchors = set(pattern.findall(anchor_map))

    assert draft_anchors, "paper/draft_v0.md should cite result anchors"
    assert draft_anchors == mapped_anchors

    for anchor in mapped_anchors:
        line = next(
            line for line in anchor_map.splitlines() if anchor in line
        )
        assert "reports/" in line or "docs/" in line, anchor


def test_paper_related_anchors_have_references() -> None:
    draft = (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8")
    references = (ROOT / "paper/references.md").read_text(encoding="utf-8")
    anchor_pattern = re.compile(r"\[RELATED: ([a-z0-9-; ]+)\]")

    draft_anchors = {
        anchor.strip()
        for group in anchor_pattern.findall(draft)
        for anchor in group.split(";")
    }
    reference_anchors = {
        anchor.strip()
        for group in anchor_pattern.findall(references)
        for anchor in group.split(";")
    }

    assert draft_anchors, "paper/draft_v0.md should cite related-work anchors"
    assert draft_anchors <= reference_anchors
    assert "[RELATED WORK:" not in draft
