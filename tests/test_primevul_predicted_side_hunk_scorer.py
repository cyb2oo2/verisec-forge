from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "evaluate_primevul_predicted_side_hunk_scorer.py"
    spec = importlib.util.spec_from_file_location("evaluate_primevul_predicted_side_hunk_scorer", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _candidate(source_id: str, rank: int, label: int, *, gold: int, risk: int, safety: int) -> dict:
    return {
        "id": f"{source_id}::hunk{rank}",
        "source_id": source_id,
        "pair_key": "pair-1",
        "gold": gold,
        "hunk_rank": rank,
        "pseudo_label": label,
        "changed_lines": 1,
        "added_lines": 1,
        "removed_lines": 1,
        "risk_support": risk,
        "safety_support": safety,
        "net_risk_support": risk - safety,
        "protection_delta": safety - risk,
        "risk_delta": risk,
        "safer_delta": safety,
        "direction_labels": ["candidate_introduces_risk"] if risk else ["candidate_adds_protection"],
        "keywords": [],
    }


def test_predicted_side_report_tracks_oracle_gap() -> None:
    module = _load_module()
    candidates = [
        _candidate("vuln", 1, 1, gold=1, risk=3, safety=0),
        _candidate("vuln", 2, 0, gold=1, risk=0, safety=3),
        _candidate("safe", 1, 1, gold=0, risk=0, safety=3),
        _candidate("safe", 2, 0, gold=0, risk=3, safety=0),
    ]
    predictions = [
        {"id": "vuln", "gold": 1, "pred": 1, "pre_coupled_pred": 0, "vuln_probability": 0.9, "pair_coupled": True},
        {"id": "safe", "gold": 0, "pred": 0, "pre_coupled_pred": 1, "vuln_probability": 0.1, "pair_coupled": True},
    ]
    scorer_report = {
        "side_aware_weights": {
            "bias": 0.0,
            "hunk_rank_inverse": 0.0,
            "changed_lines": 0.0,
            "added_lines": 0.0,
            "removed_lines": 0.0,
            "risk_support": 0.0,
            "safety_support": 0.0,
            "net_risk_support": 0.0,
            "protection_delta": 0.0,
            "risk_delta": 0.0,
            "safer_delta": 0.0,
            "direction_unclear": 0.0,
            "candidate_adds_protection": 0.0,
            "candidate_removes_protection": 0.0,
            "candidate_introduces_risk": 0.0,
            "candidate_removes_risk": 0.0,
            "keyword_count": 0.0,
            "side_is_vulnerable": 0.0,
            "aligned_support": 1.0,
            "opposing_support": -1.0,
            "alignment_margin": 0.0,
            "aligned_protection_delta": 0.0,
            "aligned_risk_delta": 0.0,
            "aligned_safer_delta": 0.0,
        }
    }

    report, scored = module.build_report(candidates, predictions, scorer_report, k_values=[1])

    assert report["side_source"]["pair_coupled_pred"]["decision_side_accuracy"] == 1.0
    assert report["side_source"]["pre_coupled_pred"]["decision_side_accuracy"] == 0.0
    assert report["coverage"]["oracle_side_aware_all"][0]["coverage"] == 1.0
    assert report["coverage"]["oracle_side_aware_matched"][0]["coverage"] == 1.0
    assert report["coverage"]["pair_coupled_predicted_side"][0]["coverage"] == 1.0
    assert report["coverage"]["pre_coupled_predicted_side"][0]["coverage"] == 0.0
    assert all("predicted_side_aware_score" in row for row in scored)
