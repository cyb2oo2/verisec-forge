import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports/decoder_stress_validation_v1.json"
MARKDOWN = ROOT / "reports/DECODER_STRESS_VALIDATION.md"


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
