from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "reproduce_primevul_calibrated_router.py"
    spec = importlib.util.spec_from_file_location("reproduce_primevul_calibrated_router", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_metric_check_matches_expected_values() -> None:
    module = _load_module()
    report = {
        "selection": {"bucket_threshold": 0.8},
        "eval": {
            "overall": {"balanced_accuracy": 0.8136},
            "group_metrics": {"group_all_correct_rate": 0.7134, "orientation_accuracy": 0.8581},
        },
        "same_split_controls": {
            "baseline_direction_aware": {
                "overall": {"balanced_accuracy": 0.8136},
                "group_metrics": {"group_all_correct_rate": 0.7101, "orientation_accuracy": 0.8514},
            }
        },
    }
    expected = {
        "selected_bucket_threshold": 0.8,
        "eval_balanced_accuracy": 0.8136,
        "eval_group_all_correct_rate": 0.7134,
        "eval_orientation_accuracy": 0.8581,
        "baseline_eval_balanced_accuracy": 0.8136,
        "baseline_group_all_correct_rate": 0.7101,
        "baseline_orientation_accuracy": 0.8514,
    }

    result = module.metric_check(report, expected)

    assert result["all_match"]
    assert result["actual"]["eval_orientation_accuracy"] == 0.8581


def test_build_command_uses_current_python_executable() -> None:
    module = _load_module()
    manifest = {
        "command": [
            ".venv/Scripts/python.exe",
            "scripts/evaluate_primevul_bucket_router_calibrated.py",
            "--dataset",
            "data.jsonl",
        ]
    }

    command = module.build_command(
        manifest,
        json_output="report.json",
        md_output="report.md",
        predictions_output="predictions.jsonl",
    )

    assert command[1:4] == ["scripts/evaluate_primevul_bucket_router_calibrated.py", "--dataset", "data.jsonl"]
    assert command[-6:] == [
        "--json-output",
        "report.json",
        "--md-output",
        "report.md",
        "--predictions-output",
        "predictions.jsonl",
    ]
