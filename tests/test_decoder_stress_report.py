import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports/decoder_stress_validation_v1.json"
MARKDOWN = ROOT / "reports/DECODER_STRESS_VALIDATION.md"


def test_decoder_stress_report_artifacts_exist() -> None:
    assert REPORT.exists()
    assert MARKDOWN.exists()
    assert REPORT.read_text(encoding="utf-8").strip()
    assert MARKDOWN.read_text(encoding="utf-8").strip()


def test_decoder_stress_report_has_required_controls() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))

    for section in ["baseline", "decoded", "randomized_pair_control"]:
        assert section in report
        assert "relation_success" in report[section]
        assert "swap_consistency" in report[section]

    stress = report["stress_metrics"]
    for metric in [
        "relation_success_delta",
        "swap_consistency_gain",
        "identity_distortion_rate",
        "randomized_pair_control_gap",
        "projected_row_coverage",
        "invalid_or_abstention_preservation",
    ]:
        assert metric in stress

    assert report["decoder_summary"]["skipped_reasons"] == {
        "unsupported_relation:context_pressure": 3600
    }


def test_decoder_stress_report_keeps_claim_boundary() -> None:
    markdown = MARKDOWN.read_text(encoding="utf-8")

    required_phrases = [
        "not evidence that the underlying model has learned stronger secure-patch reasoning",
        "not evidence by itself that the base model reasoned correctly",
        "identity distortion",
        "randomized-pair controls",
        "does not claim improved model reasoning",
    ]

    for phrase in required_phrases:
        assert phrase in markdown
