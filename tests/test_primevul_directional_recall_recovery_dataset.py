from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_directional_recall_recovery_dataset.py"
    spec = importlib.util.spec_from_file_location("build_primevul_directional_recall_recovery_dataset", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recall_recovery_dataset_oversamples_mixed_vulnerable_26plus_rows() -> None:
    module = _load_module()
    raw_rows = [
        {
            "id": "vuln",
            "pair_text": (
                "Unified diff:\n"
                "@@ -1,20 +1,20 @@\n"
                + "\n".join(f"-old_{i}" for i in range(14))
                + "\n"
                + "\n".join(f"+new_{i}" for i in range(14))
            ),
        },
        {
            "id": "safe",
            "pair_text": (
                "Unified diff:\n"
                "@@ -1,20 +1,20 @@\n"
                + "\n".join(f"-old_{i}" for i in range(14))
                + "\n"
                + "\n".join(f"+new_{i}" for i in range(14))
            ),
        },
    ]
    directional_rows = [
        {
            "id": "vuln",
            "has_vulnerability": True,
            "pair_text": "candidate_adds_protection candidate_introduces_risk",
        },
        {
            "id": "safe",
            "has_vulnerability": False,
            "pair_text": "candidate_adds_protection candidate_removes_risk",
        },
    ]

    rows, summary = module.build_dataset(
        directional_rows,
        raw_rows,
        mixed_repeats=2,
        all_vulnerable_26plus_repeats=1,
        safe_anchor_count=1,
        seed=1,
    )

    assert summary["base_rows"] == 2
    assert summary["added_rows"] == 4
    assert summary["selection"]["mixed_vulnerable_26plus"] == 1
    assert summary["labels"]["vulnerable"] == 4
    assert summary["labels"]["safe"] == 2
    assert any(row["id"].endswith("rr_mixed26_1") for row in rows)
