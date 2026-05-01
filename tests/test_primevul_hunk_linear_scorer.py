from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "train_primevul_hunk_linear_scorer.py"
    spec = importlib.util.spec_from_file_location("train_primevul_hunk_linear_scorer", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(source_id: str, rank: int, label: int, *, risk: int, safety: int, gold: int = 1) -> dict:
    return {
        "id": f"{source_id}::hunk{rank}",
        "source_id": source_id,
        "pair_key": source_id,
        "gold": gold,
        "hunk_rank": rank,
        "pseudo_label": label,
        "changed_lines": 1,
        "added_lines": 1,
        "removed_lines": 1,
        "risk_support": risk,
        "safety_support": safety,
        "net_risk_support": risk - safety,
        "protection_delta": -risk + safety,
        "risk_delta": risk,
        "safer_delta": safety,
        "direction_labels": ["candidate_introduces_risk"] if risk > safety else ["candidate_adds_protection"],
        "keywords": ["mem"] if risk else ["check"],
    }


def test_linear_scorer_can_rerank_positive_hunk() -> None:
    module = _load_module()
    train_rows = [
        _row("a", 1, 0, risk=0, safety=3),
        _row("a", 2, 1, risk=3, safety=0),
        _row("b", 1, 0, risk=0, safety=2),
        _row("b", 2, 1, risk=4, safety=0),
    ]
    eval_rows = [
        _row("c", 1, 0, risk=0, safety=3),
        _row("c", 2, 1, risk=5, safety=0),
    ]

    payload, scored_eval = module.build_report(
        train_rows,
        eval_rows,
        k_values=[1, 2],
        epochs=30,
        learning_rate=0.05,
        l2=0.0,
        seed=1,
    )

    keyword_top1 = payload["eval_coverage"]["keyword_rank"][0]["coverage"]
    linear_top1 = payload["eval_coverage"]["linear_scorer"][0]["coverage"]
    assert keyword_top1 == 0.0
    assert linear_top1 == 1.0
    assert payload["eval_coverage"]["side_aware_linear_scorer"][0]["coverage"] == 1.0
    assert "side_aware_eval_label_metrics" in payload
    assert max(row["linear_score"] for row in scored_eval if row["pseudo_label"] == 1) > max(
        row["linear_score"] for row in scored_eval if row["pseudo_label"] == 0
    )
    assert all("side_aware_linear_score" in row for row in scored_eval)
