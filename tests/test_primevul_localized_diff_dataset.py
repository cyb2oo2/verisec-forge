from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_localized_diff_dataset.py"
    spec = importlib.util.spec_from_file_location("build_primevul_localized_diff_dataset", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_localize_rows_preserves_ids_and_labels() -> None:
    module = _load_module()
    rows = [
        {
            "id": "row-1",
            "has_vulnerability": True,
            "project": "p",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-120",
            "pair_text": (
                "Task\nUnified diff:\n"
                "--- paired_counterpart\n"
                "+++ candidate\n"
                "@@ -1,1 +1,1 @@\n"
                "-strcpy(a,b);\n"
                "+bounded_copy(a,b,n);\n"
            ),
        }
    ]

    localized = module.localize_rows(rows, max_chars=200, max_hunks=1)

    assert localized[0]["id"] == "row-1"
    assert localized[0]["has_vulnerability"] is True
    assert localized[0]["pair_text_mode"] == "diff_localized"
    assert "Localized unified diff:" in localized[0]["pair_text"]
    assert "strcpy" in localized[0]["pair_text"]
