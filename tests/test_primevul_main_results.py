from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_main_results.py"
    spec = importlib.util.spec_from_file_location("build_primevul_main_results", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_main_results_summary_uses_diff_seed_rows() -> None:
    module = _load_module()
    rows = [
        {"system": "metadata-only control", "balanced_accuracy": 0.5},
        {"system": "candidate-only control", "balanced_accuracy": 0.51},
        {"system": "counterpart-only control", "balanced_accuracy": 0.52},
        {"system": "diff-only detector, dedup eval", "balanced_accuracy": 0.81},
        {"system": "diff-only detector, seed7 dedup", "balanced_accuracy": 0.84},
        {"system": "diff-only detector, seed99 dedup", "balanced_accuracy": 0.83},
    ]

    summary = module.build_summary(rows)

    assert summary["diff_seed_balanced_accuracy_mean"] == 0.8267
    assert summary["diff_seed_balanced_accuracy_min"] == 0.81
    assert summary["diff_seed_balanced_accuracy_max"] == 0.84
    assert summary["negative_control_best_balanced_accuracy_max"] == 0.52


def test_render_markdown_includes_core_columns() -> None:
    module = _load_module()
    rows = [
        {
            "system": "diff-only detector",
            "threshold": 0.6,
            "accuracy": 0.81,
            "recall": 0.8,
            "specificity": 0.82,
            "precision": 0.83,
            "f1": 0.82,
            "balanced_accuracy": 0.81,
            "note": "best",
        }
    ]
    summary = {
        "headline": "headline",
        "diff_seed_balanced_accuracy_mean": 0.81,
        "diff_seed_balanced_accuracy_min": 0.81,
        "diff_seed_balanced_accuracy_max": 0.81,
        "negative_control_best_balanced_accuracy_max": 0.52,
    }

    markdown = module.render_markdown(rows, summary)

    assert "| System | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy | Note |" in markdown
    assert "diff-only detector" in markdown


def test_from_report_computes_missing_f1() -> None:
    module = _load_module()
    report_path = Path("artifacts") / "test_primevul_main_results_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        '{"presence_accuracy": 0.9, "vulnerable_recall": 0.8, "safe_specificity": 1.0, "precision": 0.6}',
        encoding="utf-8",
    )

    row = module._from_report("model", str(report_path))

    assert row["f1"] == 0.6857
