from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "analyze_primevul_diff_failures.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_diff_failures", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_failure_analysis_uses_requested_threshold() -> None:
    module = _load_module()
    dataset_rows = [
        {
            "id": "safe",
            "has_vulnerability": False,
            "project": "proj-a",
            "vulnerability_type": "cwe-79",
            "pair_key": "pair-1",
            "pair_text": "Unified diff:\n--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new",
        },
        {
            "id": "vuln",
            "has_vulnerability": True,
            "project": "proj-b",
            "vulnerability_type": "cwe-787",
            "pair_key": "pair-1",
            "pair_text": "Unified diff:\n--- a\n+++ b\n@@ -1 +1,2 @@\n-old\n+new\n+extra",
        },
    ]
    prediction_rows = [
        {"id": "safe", "gold": 0, "vuln_probability": 0.55},
        {"id": "vuln", "gold": 1, "vuln_probability": 0.58},
    ]

    payload = module.build_failure_analysis(dataset_rows, prediction_rows, threshold=0.6)

    assert payload["summary"]["tn"] == 1
    assert payload["summary"]["fn"] == 1
    assert payload["summary"]["accuracy"] == 0.5
    assert payload["group_metrics"]["unique_pair_count"] == 1
    assert payload["group_metrics"]["group_all_correct_rate"] == 0.0
    assert payload["group_metrics"]["orientation_accuracy"] == 1.0
    assert payload["top_false_negatives"][0]["id"] == "vuln"


def test_diff_stats_count_changed_lines_without_headers() -> None:
    module = _load_module()

    stats = module._diff_stats("Unified diff:\n--- old\n+++ new\n@@ -1,2 +1,3 @@\n-a\n-b\n+c\n+d\n+e")

    assert stats["removed_lines"] == 2
    assert stats["added_lines"] == 3
    assert stats["changed_lines"] == 5
    assert stats["hunks"] == 1


def test_render_markdown_includes_failure_sections() -> None:
    module = _load_module()
    payload = {
        "summary": {
            "threshold": 0.6,
            "accuracy": 0.8,
            "recall": 0.7,
            "specificity": 0.9,
            "precision": 0.75,
            "fp": 1,
            "fn": 2,
            "num_examples": 10,
        },
        "by_cwe": [],
        "group_metrics": {
            "unique_pair_count": 1,
            "group_all_correct_rate": 0.5,
            "orientation_accuracy": 1.0,
        },
        "by_project": [],
        "by_changed_line_bucket": [],
        "by_confidence_bucket": [],
        "top_false_positives": [],
        "top_false_negatives": [],
    }

    markdown = module.render_markdown(payload)

    assert "PrimeVul Paired Diff Failure Analysis" in markdown
    assert "Group all-correct rate" in markdown
    assert "Highest-Confidence False Positives" in markdown
    assert "Lowest-Probability False Negatives" in markdown
