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
        {"system": "diff-only detector, edge-focus", "balanced_accuracy": 0.83},
        {"system": "diff-only detector, edge-focus seed7", "balanced_accuracy": 0.81},
        {"system": "diff-only detector, edge-focus seed99", "balanced_accuracy": 0.82},
    ]

    summary = module.build_summary(rows)

    assert summary["diff_seed_balanced_accuracy_mean"] == 0.8267
    assert summary["diff_seed_balanced_accuracy_min"] == 0.81
    assert summary["diff_seed_balanced_accuracy_max"] == 0.84
    assert summary["edge_focus_seed_balanced_accuracy_mean"] == 0.82
    assert summary["edge_focus_seed_balanced_accuracy_min"] == 0.81
    assert summary["edge_focus_seed_balanced_accuracy_max"] == 0.83
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
        "edge_focus_seed_balanced_accuracy_mean": 0.82,
        "edge_focus_seed_balanced_accuracy_min": 0.81,
        "edge_focus_seed_balanced_accuracy_max": 0.83,
        "negative_control_best_balanced_accuracy_max": 0.52,
    }

    markdown = module.render_markdown(rows, summary)

    assert "| System | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy | Note |" in markdown
    assert "diff-only detector" in markdown
    assert "| System | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy | Note |" in markdown


def test_build_rows_includes_no_metadata_control(monkeypatch) -> None:
    module = _load_module()
    calls: list[tuple[str, str]] = []

    def fake_from_report(label: str, path: str, **kwargs):
        calls.append((label, path))
        return {
            "system": label,
            "threshold": kwargs.get("threshold"),
            "accuracy": 0.5,
            "recall": 0.5,
            "specificity": 0.5,
            "precision": 0.5,
            "f1": 0.5,
            "balanced_accuracy": 0.5,
            "note": kwargs.get("note", ""),
        }

    monkeypatch.setattr(module, "_from_report", fake_from_report)
    monkeypatch.setattr(module, "_from_sweep", fake_from_report)

    rows = module.build_rows()

    assert any(row["system"] == "diff-only detector, no metadata" for row in rows)
    assert any(row["system"] == "diff-only checkpoint on localized eval" for row in rows)
    assert any(row["system"] == "localized-diff detector" for row in rows)
    assert any(row["system"] == "contrastive-window detector" for row in rows)
    assert any(row["system"] == "direction-aware bucket router" for row in rows)
    assert any(row["system"] == "diff-only detector, edge-focus" for row in rows)
    assert any(row["system"] == "diff-only detector, edge-focus seed7" for row in rows)
    assert any(row["system"] == "diff-only detector, edge-focus seed99" for row in rows)


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


def test_from_nested_report_reads_router_overall_metrics() -> None:
    module = _load_module()
    report_path = Path("artifacts") / "test_primevul_router_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        '{"thresholds": {"bucket": 0.8}, "overall": {"presence_accuracy": 0.82, "vulnerable_recall": 0.83, "safe_specificity": 0.81, "precision": 0.8, "f1": 0.815, "balanced_accuracy": 0.82}}',
        encoding="utf-8",
    )

    row = module._from_nested_report("router", str(report_path))

    assert row["threshold"] == 0.8
    assert row["balanced_accuracy"] == 0.82
    assert row["recall"] == 0.83
