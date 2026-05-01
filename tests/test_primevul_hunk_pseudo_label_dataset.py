from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_hunk_pseudo_label_dataset.py"
    spec = importlib.util.spec_from_file_location("build_primevul_hunk_pseudo_label_dataset", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hunk_pseudo_labels_follow_gold_side_direction() -> None:
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
                " static void f() {\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, strlen(src)); sprintf(buf, src);\n"
                " }\n"
            ),
        },
        {
            "id": "safe",
            "has_vulnerability": False,
            "pair_key": "pair-2",
            "project": "p",
            "cve": "CVE-2",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,3 +1,3 @@\n"
                " static void f() {\n"
                "-  memcpy(dst, src, len);\n"
                "+  checked_copy(dst, src, len);\n"
                " }\n"
            ),
        },
    ]

    hunk_rows = module.build_hunk_rows(rows, max_hunks=1)
    summary = module.summarize(hunk_rows, coverage_k=[1])

    assert len(hunk_rows) == 2
    assert all(row["pseudo_label"] == 1 for row in hunk_rows)
    assert summary["positive_rate"] == 1.0
    assert summary["coverage_at_k"][0]["coverage"] == 1.0


def test_hunk_pseudo_label_coverage_can_miss_top_rank() -> None:
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
                "@@ -1,3 +1,3 @@\n"
                " static void f() {\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, strlen(src)); sprintf(buf, src);\n"
                " }\n"
                "@@ -9,3 +9,3 @@\n"
                " static void g() {\n"
                "-  memcpy(dst, src, len);\n"
                "+  checked_copy(dst, src, len);\n"
                " }\n"
            ),
        },
    ]

    hunk_rows = module.build_hunk_rows(rows, max_hunks=2)
    summary = module.summarize(hunk_rows, coverage_k=[1, 2])

    assert [row["pseudo_label"] for row in hunk_rows] == [0, 1]
    assert summary["coverage_at_k"][0]["coverage"] == 0.0
    assert summary["coverage_at_k"][1]["coverage"] == 1.0
