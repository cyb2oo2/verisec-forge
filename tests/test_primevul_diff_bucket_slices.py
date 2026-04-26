from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_diff_bucket_slices.py"
    spec = importlib.util.spec_from_file_location("build_primevul_diff_bucket_slices", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(row_id: str, *, vulnerable: bool, changed_lines: int) -> dict[str, object]:
    removed = "\n".join(f"-old{i}" for i in range(changed_lines // 2))
    added = "\n".join(f"+new{i}" for i in range(changed_lines - changed_lines // 2))
    return {
        "id": row_id,
        "has_vulnerability": vulnerable,
        "pair_text": f"Unified diff:\n--- a\n+++ b\n@@ -1 +1 @@\n{removed}\n{added}",
    }


def test_add_bucket_assigns_changed_line_bucket() -> None:
    module = _load_module()

    enriched = module.add_bucket(_row("r1", vulnerable=True, changed_lines=27))

    assert enriched["changed_lines"] == 27
    assert enriched["changed_line_bucket"] == "26+"


def test_build_edge_focused_train_balances_labels() -> None:
    module = _load_module()
    rows = []
    for idx in range(10):
        rows.append(module.add_bucket(_row(f"edge-pos-{idx}", vulnerable=True, changed_lines=1)))
        rows.append(module.add_bucket(_row(f"edge-neg-{idx}", vulnerable=False, changed_lines=28)))
        rows.append(module.add_bucket(_row(f"mid-pos-{idx}", vulnerable=True, changed_lines=6)))
        rows.append(module.add_bucket(_row(f"mid-neg-{idx}", vulnerable=False, changed_lines=6)))

    selected, summary = module.build_edge_focused_train(rows, total_count=20, edge_share=0.6, seed=7)

    assert len(selected) == 20
    assert sum(1 for row in selected if row["has_vulnerability"]) == 10
    assert sum(1 for row in selected if not row["has_vulnerability"]) == 10
    assert summary["edge_selected"]["00-02"]["vulnerable"] == 6
    assert summary["edge_selected"]["26+"]["safe"] == 6
    assert summary["edge_sampling"]["replacement_used"] is False
    assert summary["selected_unique_summary"]["duplicate_rows_from_resampling"] == 0


def test_build_edge_focused_train_oversamples_when_edge_is_sparse() -> None:
    module = _load_module()
    rows = []
    for idx in range(2):
        rows.append(module.add_bucket(_row(f"edge-pos-{idx}", vulnerable=True, changed_lines=1)))
        rows.append(module.add_bucket(_row(f"edge-neg-{idx}", vulnerable=False, changed_lines=28)))
    for idx in range(10):
        rows.append(module.add_bucket(_row(f"mid-pos-{idx}", vulnerable=True, changed_lines=6)))
        rows.append(module.add_bucket(_row(f"mid-neg-{idx}", vulnerable=False, changed_lines=6)))

    selected, summary = module.build_edge_focused_train(rows, total_count=20, edge_share=0.6, seed=7)

    assert len(selected) == 20
    assert sum(1 for row in selected if row["has_vulnerability"]) == 10
    assert sum(1 for row in selected if not row["has_vulnerability"]) == 10
    assert summary["edge_sampling"]["replacement_used"] is True
    assert summary["selected_unique_summary"]["duplicate_rows_from_resampling"] > 0


def test_summarize_counts_bucket_labels() -> None:
    module = _load_module()
    rows = [
        module.add_bucket(_row("a", vulnerable=True, changed_lines=2)),
        module.add_bucket(_row("b", vulnerable=False, changed_lines=2)),
        module.add_bucket(_row("c", vulnerable=False, changed_lines=11)),
    ]

    summary = module.summarize(rows)

    assert summary["00-02"]["total"] == 2
    assert summary["00-02"]["vulnerable"] == 1
    assert summary["11-25"]["safe"] == 1
