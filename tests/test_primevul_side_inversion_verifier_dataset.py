from __future__ import annotations

from scripts.build_primevul_side_inversion_verifier_dataset import build_rows, render_prompt, summarize, target_for_row


def queue_row(accept: bool = True) -> dict:
    return {
        "seed": 7,
        "rank": 1,
        "pair_key": "project|commit|CVE-1",
        "side_model_score": 0.9,
        "gold_invert": int(accept),
        "is_true_inversion_candidate": accept,
        "side_a_probability": 0.8,
        "side_b_probability": 0.2,
        "probability_gap": 0.6,
        "side_a_windows": [
            {
                "header": "@@ a @@",
                "direction_labels": ["candidate_adds_protection"],
                "risk_support": 0,
                "safety_support": 2,
                "removed_preview": [],
                "added_preview": ["check(x);"],
            }
        ],
        "side_b_windows": [
            {
                "header": "@@ b @@",
                "direction_labels": ["candidate_removes_protection"],
                "risk_support": 2,
                "safety_support": 0,
                "removed_preview": ["check(x);"],
                "added_preview": [],
            }
        ],
    }


def test_target_for_row_accepts_true_inversion() -> None:
    target = target_for_row(queue_row(True))

    assert target["accept_flip"] is True
    assert target["evidence_side"] == "B"


def test_render_prompt_contains_contract_and_windows() -> None:
    prompt = render_prompt(queue_row(True))

    assert "accept_flip" in prompt
    assert "Side A windows" in prompt
    assert "Side B windows" in prompt


def test_build_rows_and_summarize() -> None:
    rows = build_rows([queue_row(True), queue_row(False)])
    summary = summarize(rows)

    assert rows[0]["accept_flip"] is True
    assert rows[1]["accept_flip"] is False
    assert summary["rows"] == 2
    assert summary["accept_flip_rows"] == 1
