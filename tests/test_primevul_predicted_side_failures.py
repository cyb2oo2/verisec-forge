from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "analyze_primevul_predicted_side_failures.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_predicted_side_failures", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_predicted_side_failure_taxonomy_counts_wrong_sides() -> None:
    module = _load_module()
    hunk_rows = [
        {
            "source_id": "a",
            "project": "proj",
            "vulnerability_type": "cwe-120",
            "pseudo_label": 1,
            "header": "h1",
            "direction_labels": ["candidate_introduces_risk"],
            "risk_support": 2,
            "safety_support": 0,
            "predicted_side_aware_score": 3.0,
        },
        {
            "source_id": "b",
            "project": "proj",
            "vulnerability_type": "cwe-79",
            "pseudo_label": 0,
            "header": "h2",
            "direction_labels": ["candidate_adds_protection"],
            "risk_support": 0,
            "safety_support": 2,
            "predicted_side_aware_score": 2.0,
        },
    ]
    predictions = [
        {"id": "a", "gold": 1, "pred": 0, "changed_line_bucket": "26+", "pair_probability_gap": 0.9, "route": "default"},
        {"id": "b", "gold": 0, "pred": 0, "changed_line_bucket": "03-05", "pair_probability_gap": 0.1, "route": "default"},
    ]

    payload = module.summarize_sources(hunk_rows, predictions, top_n=5)

    assert payload["summary"]["matched_sources"] == 2
    assert payload["summary"]["wrong_sources"] == 1
    assert payload["summary"]["false_negatives"] == 1
    assert payload["wrong_breakdowns"]["by_changed_line_bucket"][0] == {"value": "26+", "count": 1}
    markdown = module.render_markdown(payload)
    assert "High-Score Wrong Examples" in markdown
    assert "upstream side-decision failures" in markdown
