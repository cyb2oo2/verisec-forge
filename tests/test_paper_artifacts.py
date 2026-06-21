from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_paper_draft_packet_exists() -> None:
    expected = [
        "paper/README.md",
        "paper/abstract.md",
        "paper/outline.md",
        "paper/main_claims.md",
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
