from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "reproduce_primevul_evidence_coupled.py"
    spec = importlib.util.spec_from_file_location("reproduce_primevul_evidence_coupled", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_metric_check_reads_expected_report_values() -> None:
    module = _load_module()
    expected = {
        "hunk_linear_top1": 0.6178,
        "hunk_side_aware_top1": 0.7073,
        "predicted_side_accuracy": 0.8488,
        "oracle_matched_top1": 0.7184,
        "predicted_side_top1": 0.6555,
        "side_correct_top1": 0.761,
        "side_wrong_top1": 0.0632,
        "side_wrong_rows": 190,
        "side_wrong_false_positives": 95,
        "side_wrong_false_negatives": 95,
        "confident_inversion_rows": 86,
        "confident_inversion_pair_groups": 43,
        "confident_inversion_false_positives": 43,
        "confident_inversion_false_negatives": 43,
        "confident_inversion_avg_gap": 0.8225,
    }

    checks = module.metric_check(expected)

    assert checks["all_match"]
