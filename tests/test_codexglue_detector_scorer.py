from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "evaluate_codexglue_detector_scorer.py"
    spec = importlib.util.spec_from_file_location("evaluate_codexglue_detector_scorer", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evaluate_detector_scorer_applies_second_stage_gate() -> None:
    module = _load_module()

    dataset_rows = {
        "vuln-supported": {"id": "vuln-supported", "has_vulnerability": True},
        "vuln-missed": {"id": "vuln-missed", "has_vulnerability": True},
        "safe-rejected": {"id": "safe-rejected", "has_vulnerability": False},
        "safe-ignored": {"id": "safe-ignored", "has_vulnerability": False},
    }
    probability_rows = {
        "vuln-supported": {"id": "vuln-supported", "vuln_probability": 0.9},
        "vuln-missed": {"id": "vuln-missed", "vuln_probability": 0.4},
        "safe-rejected": {"id": "safe-rejected", "vuln_probability": 0.8},
        "safe-ignored": {"id": "safe-ignored", "vuln_probability": 0.1},
    }
    scorer_rows = {
        "vuln-supported": {"id": "vuln-supported", "supported_probability": 0.7},
        "safe-rejected": {"id": "safe-rejected", "supported_probability": 0.4},
    }

    report = module.evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["tp"] == 1
    assert report["tn"] == 2
    assert report["fp"] == 0
    assert report["fn"] == 1
    assert report["detector_positive_rate"] == 0.5
    assert report["scorer_positive_rate"] == 0.25
    assert report["presence_accuracy"] == 0.75
    assert report["vulnerable_recall"] == 0.5
    assert report["safe_specificity"] == 1.0
    assert report["precision"] == 1.0
    assert report["f1"] == 0.6667


def test_evaluate_detector_scorer_reports_unsupported_positive_share() -> None:
    module = _load_module()

    dataset_rows = {
        "vuln-supported": {"id": "vuln-supported", "has_vulnerability": True},
        "safe-supported": {"id": "safe-supported", "has_vulnerability": False},
    }
    probability_rows = {
        "vuln-supported": {"id": "vuln-supported", "vuln_probability": 0.9},
        "safe-supported": {"id": "safe-supported", "vuln_probability": 0.8},
    }
    scorer_rows = {
        "vuln-supported": {"id": "vuln-supported", "supported_probability": 0.9},
        "safe-supported": {"id": "safe-supported", "vuln_probability": 0.8},
    }

    report = module.evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["tp"] == 1
    assert report["fp"] == 1
    assert report["unsupported_positive_share"] == 0.5
    assert report["precision"] == 0.5
