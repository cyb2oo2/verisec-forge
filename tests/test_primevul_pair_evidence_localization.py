from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "analyze_primevul_pair_evidence_localization.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_pair_evidence_localization", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_support_scores_separate_risky_and_safe_hunks() -> None:
    module = _load_module()

    risky = {
        "protection_delta": -1,
        "risk_delta": 2,
        "safer_delta": 0,
    }
    safe = {
        "protection_delta": 2,
        "risk_delta": -1,
        "safer_delta": 1,
    }

    assert module.support_scores(risky)["risk_support"] == 3
    assert module.support_scores(risky)["safety_support"] == 0
    assert module.support_scores(safe)["risk_support"] == 0
    assert module.support_scores(safe)["safety_support"] == 4


def test_pair_evidence_report_marks_supported_predictions() -> None:
    module = _load_module()
    dataset_rows = [
        {
            "id": "vuln",
            "has_vulnerability": True,
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_key": "pair-1",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,3 +1,3 @@\n"
                " static void f() {\n"
                "-  check_len(len);\n"
                "+  memcpy(dst, src, len);\n"
                " }\n"
            ),
        },
        {
            "id": "safe",
            "has_vulnerability": False,
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_key": "pair-1",
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
    prediction_rows = [
        {"id": "vuln", "gold": 1, "pred": 1, "pair_key": "pair-1", "vuln_probability": 0.9, "pair_coupled": True},
        {"id": "safe", "gold": 0, "pred": 0, "pair_key": "pair-1", "vuln_probability": 0.1, "pair_coupled": True},
    ]

    payload = module.build_report(dataset_rows, prediction_rows, hunk_limit=1, example_limit=2)

    assert payload["summary"]["accuracy"] == 1.0
    assert payload["summary"]["support_rate"] == 1.0
    assert payload["coupled_summary"]["unique_pair_count"] == 1
