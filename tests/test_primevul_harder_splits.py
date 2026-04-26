from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_harder_splits.py"
    spec = importlib.util.spec_from_file_location("build_primevul_harder_splits", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_project_disjoint_excludes_seen_train_projects_and_balances_labels() -> None:
    module = _load_module()
    train_rows = [
        {"id": "tr-1", "project": "linux", "has_vulnerability": True},
        {"id": "tr-2", "project": "openssl", "has_vulnerability": False},
    ]
    input_rows = [
        {"id": "seen-pos", "split": "eval", "project": "linux", "has_vulnerability": True},
        {"id": "new-pos", "split": "eval", "project": "curl", "has_vulnerability": True},
        {"id": "new-neg", "split": "eval", "project": "curl", "has_vulnerability": False},
        {"id": "new-neg-2", "split": "eval", "project": "nginx", "has_vulnerability": False},
    ]

    selected, summary = module.build_project_disjoint(
        input_rows=input_rows,
        train_rows=train_rows,
        candidate_split="eval",
        per_label_count=1,
        seed=7,
    )

    assert summary["project_overlap_with_train"] == 0
    assert summary["selected"] == {"vulnerable": 1, "safe": 1, "total": 2}
    assert {row["project"] for row in selected}.isdisjoint({"linux", "openssl"})


def test_paired_eval_samples_balanced_rows_from_requested_split() -> None:
    module = _load_module()
    input_rows = [
        {"id": "eval-pos-1", "split": "eval", "project": "a", "has_vulnerability": True},
        {"id": "eval-pos-2", "split": "eval", "project": "b", "has_vulnerability": True},
        {"id": "eval-neg-1", "split": "eval", "project": "a", "has_vulnerability": False},
        {"id": "train-neg", "split": "train", "project": "a", "has_vulnerability": False},
    ]

    selected, summary = module.build_paired_eval(
        input_rows=input_rows,
        candidate_split="eval",
        per_label_count=2,
        seed=7,
    )

    assert summary["selected"] == {"vulnerable": 1, "safe": 1, "total": 2}
    assert {row["split"] for row in selected} == {"eval"}
