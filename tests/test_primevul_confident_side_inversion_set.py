from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_confident_side_inversion_set.py"
    spec = importlib.util.spec_from_file_location("build_primevul_confident_side_inversion_set", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_inversion_rows_filters_wrong_high_gap_predictions() -> None:
    module = _load_module()
    dataset = [
        {
            "id": "a",
            "pair_key": "p1",
            "project": "linux",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-787",
            "pair_text": "diff",
            "code": "code",
        },
        {"id": "b", "pair_key": "p2", "project": "qemu", "cve": "CVE-2", "vulnerability_type": "cwe-125"},
    ]
    predictions = [
        {"id": "a", "gold": 1, "pred": 0, "pair_probability_gap": 0.7, "vuln_probability": 0.1},
        {"id": "b", "gold": 0, "pred": 1, "pair_probability_gap": 0.2, "vuln_probability": 0.8},
    ]

    rows = module.build_inversion_rows(dataset, predictions, min_gap=0.5)
    payload = module.summarize(rows, min_gap=0.5, top_n=5)

    assert len(rows) == 1
    assert rows[0]["id"] == "a"
    assert rows[0]["mistake_type"] == "false_negative"
    assert rows[0]["calibration_target"] == 1
    assert payload["summary"]["false_negatives"] == 1
    assert "targeted calibration" in module.render_markdown(payload)
