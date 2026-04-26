from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_evidence_scorer_dataset.py"
    spec = importlib.util.spec_from_file_location("build_primevul_evidence_scorer_dataset", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_support_scorer_input_modes_isolate_probability_and_code() -> None:
    module = _load_module()
    code = "memcpy(dst, src, len);"

    full = module.build_text(code=code, language="c", probability=0.91, input_mode="full")
    no_probability = module.build_text(code=code, language="c", probability=0.91, input_mode="no_probability")
    probability_only = module.build_text(code=code, language="c", probability=0.91, input_mode="probability_only")
    code_only = module.build_text(code=code, language="c", probability=0.91, input_mode="code_only")
    heuristic_only = module.build_text(code=code, language="c", probability=0.91, input_mode="heuristic_only")
    alert_validity = module.build_text(
        code=code,
        language="c",
        probability=0.91,
        input_mode="no_probability",
        label_mode="alert_validity",
    )

    assert "Detector vulnerability probability" in full
    assert code in full
    assert "Detector vulnerability probability" not in no_probability
    assert code in no_probability
    assert "Detector vulnerability probability" in probability_only
    assert code not in probability_only
    assert code_only == f"language: c\ncode:\n{code}"
    assert "memcpy: 1" in heuristic_only
    assert code not in heuristic_only
    assert "true vulnerability alert" in alert_validity


def test_balance_support_rows_keeps_hard_negatives_and_downsamples_positives() -> None:
    module = _load_module()
    rows = [
        {
            "id": "pos-high",
            "has_vulnerability": True,
            "detector_probability": 0.8,
            "heuristic_keyword_count": 8,
        },
        {
            "id": "pos-low",
            "has_vulnerability": True,
            "detector_probability": 0.9,
            "heuristic_keyword_count": 1,
        },
        {
            "id": "neg-hard",
            "has_vulnerability": False,
            "detector_probability": 0.99,
            "heuristic_keyword_count": 5,
        },
        {
            "id": "neg-easy",
            "has_vulnerability": False,
            "detector_probability": 0.6,
            "heuristic_keyword_count": 0,
        },
    ]

    balanced = module.balance_support_rows(rows, positive_to_negative_ratio=0.5)

    assert [row["id"] for row in balanced] == ["pos-high", "neg-hard", "neg-easy"]
