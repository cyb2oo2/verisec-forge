from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "analyze_primevul_large_diff_windows.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_large_diff_windows", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_large_diff_window_analysis_extracts_fp_and_fn_hunks() -> None:
    module = _load_module()
    dataset_rows = [
        {
            "id": "safe",
            "has_vulnerability": False,
            "project": "p",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,1 +1,1 @@\n"
                "-strcpy(dst, src);\n"
                "+bounded_copy(dst, src, len);\n"
            ),
        },
        {
            "id": "vuln",
            "has_vulnerability": True,
            "project": "p",
            "vulnerability_type": "cwe-787",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -2,1 +2,1 @@\n"
                "-check_len(len);\n"
                "+memcpy(dst, src, len);\n"
            ),
        },
    ]
    prediction_rows = [
        {"id": "safe", "gold": 0, "vuln_probability": 0.9},
        {"id": "vuln", "gold": 1, "vuln_probability": 0.1},
    ]

    payload = module.build_analysis(dataset_rows, prediction_rows, threshold=0.5, hunk_limit=1)

    assert payload["summary"]["fp"] == 1
    assert payload["summary"]["fn"] == 1
    assert payload["top_false_positives"][0]["top_hunks"][0]["keywords"]
    assert payload["top_false_negatives"][0]["top_hunks"][0]["keywords"]
