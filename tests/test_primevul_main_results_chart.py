from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_main_results_chart.py"
    spec = importlib.util.spec_from_file_location("build_primevul_main_results_chart", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_chart_svg_contains_rows_and_values() -> None:
    module = _load_module()
    rows = [
        {"system": "metadata-only control", "balanced_accuracy": 0.5022, "note": "negative control"},
        {"system": "diff-only detector, seed7 dedup", "balanced_accuracy": 0.8382, "note": "multi-seed stability"},
    ]

    svg = module.render_svg(rows)

    assert "<svg" in svg
    assert "metadata-only control" in svg
    assert "diff-only detector, seed7 dedup" in svg
    assert "0.8382" in svg
