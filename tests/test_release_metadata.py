from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CITATION = ROOT / "CITATION.cff"
RELEASE_NOTES = ROOT / "docs" / "RELEASE_V0_1_NOTES.md"
RELEASE_CHECKLIST = ROOT / "docs" / "RELEASE_CHECKLIST.md"
RELEASE_BODY = ROOT / "docs" / "RELEASE_V0_1_BODY.md"
README = ROOT / "README.md"


def test_citation_title_is_relation_preserving_not_benchmark_framed() -> None:
    citation = CITATION.read_text(encoding="utf-8")

    assert (
        'title: "VeriSec Forge: Relation-Preserving Secure Patch Reasoning"'
        in citation
    )
    assert "Secure Code Benchmark" not in citation
    assert "leaderboard" in citation
    assert "model-quality benchmark" in citation
    assert "license: Apache-2.0" in citation
