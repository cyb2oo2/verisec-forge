from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "analyze_primevul_candidate_recall.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_candidate_recall", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_line_window_candidates_can_recover_sub_hunk_signal() -> None:
    module = _load_module()
    rows = [
        {
            "id": "safe",
            "has_vulnerability": False,
            "pair_key": "pair-1",
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,5 +1,5 @@\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, strlen(src)); sprintf(buf, src);\n"
                "-  memcpy(dst, src, len);\n"
                "+  checked_copy(dst, src, len);\n"
            ),
        }
    ]

    payload = module.compare_strategies(
        rows,
        strategies=["hunk", "line_window"],
        max_candidates=4,
        window_size=2,
        coverage_k=[1, 2, 4],
    )

    assert payload["strategies"]["hunk"]["coverage_at_k"][0]["coverage"] == 0.0
    assert payload["strategies"]["line_window"]["coverage_at_k"][0]["coverage"] == 0.0
    assert payload["strategies"]["line_window"]["coverage_at_k"][2]["coverage"] == 1.0


def test_hunk_plus_window_reports_expected_strategy_metadata() -> None:
    module = _load_module()
    rows = [
        {
            "id": "vuln",
            "has_vulnerability": True,
            "pair_key": "pair-1",
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,3 +1,3 @@\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, len);\n"
            ),
        }
    ]

    candidate_rows = module.build_candidate_rows(rows, strategy="hunk_plus_window", max_candidates=3, window_size=1)

    assert candidate_rows
    assert all(row["candidate_strategy"] == "hunk_plus_window" for row in candidate_rows)
    assert all(row["source_id"] == "vuln" for row in candidate_rows)


def test_build_rows_by_strategy_returns_requested_candidate_sets() -> None:
    module = _load_module()
    rows = [
        {
            "id": "vuln",
            "has_vulnerability": True,
            "pair_key": "pair-1",
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,3 +1,3 @@\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, len);\n"
            ),
        }
    ]

    rows_by_strategy = module.build_rows_by_strategy(
        rows,
        strategies=["hunk", "hunk_plus_window"],
        max_candidates=2,
        window_size=1,
    )

    assert set(rows_by_strategy) == {"hunk", "hunk_plus_window"}
    assert rows_by_strategy["hunk"]
    assert rows_by_strategy["hunk_plus_window"]
