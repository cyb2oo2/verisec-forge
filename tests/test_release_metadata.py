from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CITATION = ROOT / "CITATION.cff"
RELEASE_NOTES = ROOT / "docs" / "RELEASE_V0_1_NOTES.md"
RELEASE_CHECKLIST = ROOT / "docs" / "RELEASE_CHECKLIST.md"
RELEASE_BODY = ROOT / "docs" / "RELEASE_V0_1_BODY.md"
README = ROOT / "README.md"


def test_release_metadata_files_exist() -> None:
    assert CITATION.exists()
    assert RELEASE_NOTES.exists()
    assert RELEASE_CHECKLIST.exists()
    assert RELEASE_BODY.exists()


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


def test_release_notes_keep_artifact_boundary() -> None:
    notes = RELEASE_NOTES.read_text(encoding="utf-8")
    checklist = RELEASE_CHECKLIST.read_text(encoding="utf-8")
    combined = " ".join(f"{notes}\n{checklist}".split())

    required = [
        "not create a release, DOI, leaderboard, or preprint",
        "Not a deployed vulnerability scanner",
        "Not a leaderboard",
        "Not a model-quality benchmark release",
        "Not evidence that decoding improves model reasoning",
        "not be cited as evidence that a model has improved vulnerability detection performance",
        "does not change experiments, claims, benchmark artifacts",
    ]
    for phrase in required:
        assert phrase in combined

    forbidden = [
        "state-of-the-art",
        "new field",
        "solves secure patch reasoning",
    ]
    lower_notes = notes.lower()
    for phrase in forbidden:
        assert phrase not in lower_notes


def test_release_body_is_draft_only_and_keeps_boundary() -> None:
    body = RELEASE_BODY.read_text(encoding="utf-8")

    required = [
        "It is staged here for review and is not published as a release.",
        "Not a deployed vulnerability scanner.",
        "Not a leaderboard.",
        "Not a model-quality benchmark release.",
        "Not evidence that decoding improves model reasoning.",
        "do not initiate archival, request a DOI, or create a Zenodo entry",
    ]
    for phrase in required:
        assert phrase in body

    forbidden = [
        "state-of-the-art",
        "new field",
        "solves secure patch reasoning",
    ]
    lower_body = body.lower()
    for phrase in forbidden:
        assert phrase not in lower_body


def test_readme_links_release_metadata() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "[CITATION.cff](CITATION.cff)" in readme
    assert "[v0.1 release notes](docs/RELEASE_V0_1_NOTES.md)" in readme
    assert "[release checklist](docs/RELEASE_CHECKLIST.md)" in readme
