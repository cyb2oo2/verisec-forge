from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/EXTERNAL_MODEL_REPORT_CARD.md"
TEMPLATE = ROOT / "reports/templates/external_model_report_card.md"
GUIDE = ROOT / "docs/EXTERNAL_PARTICIPATION_GUIDE.md"
INDEX = ROOT / "reports/RESULTS_INDEX.md"


def test_external_model_report_card_files_exist() -> None:
    for path in [DOC, TEMPLATE]:
        assert path.exists(), path
        assert path.read_text(encoding="utf-8").strip(), path


def test_external_model_report_card_preserves_claim_boundaries() -> None:
    combined = "\n".join(
        [
            DOC.read_text(encoding="utf-8"),
            TEMPLATE.read_text(encoding="utf-8"),
        ]
    )

    required_phrases = [
        "not a new benchmark",
        "not a leaderboard row",
        "not a model-quality benchmark",
        "not make tokenizer-neutral runtime visibility claims",
        "not present this report card as endorsement",
    ]

    for phrase in required_phrases:
        assert phrase in combined


def test_external_model_report_card_requires_reproducibility_fields() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    required_fields = [
        "Model name:",
        "Prediction file:",
        "Evaluation report:",
        "Prediction command or script:",
        "`supports_abstention` setting:",
        "Was runtime accounting materialized for this exact model/tokenizer?",
    ]

    for field in required_fields:
        assert field in template


def test_external_model_report_card_is_linked_from_public_entry_points() -> None:
    assert "reports/templates/external_model_report_card.md" in GUIDE.read_text(
        encoding="utf-8"
    )
    assert "docs/EXTERNAL_MODEL_REPORT_CARD.md" in INDEX.read_text(
        encoding="utf-8"
    )
