from vrf.readout_classifier import (
    changed_line_spans,
    pooling_mask_from_offsets,
)
from scripts.train_readout_ablation import length_bucket_order, pair_metrics


def test_changed_line_spans_ignore_diff_headers():
    text = "--- Side A\n+++ Side B\n context\n-old();\n+new();\n"
    selected = [text[start:end] for start, end in changed_line_spans(text)]

    assert selected == ["-old();", "+new();"]


def test_pooling_mask_selects_overlapping_tokens():
    offsets = [(0, 0), (0, 4), (4, 8), (8, 12)]
    mask = pooling_mask_from_offsets(offsets, [(3, 9)])

    assert mask == [0, 1, 1, 1]


def test_length_bucket_order_is_deterministic():
    rows = [
        {"pair_key": str(index), "pair_length": index}
        for index in range(40)
    ]

    assert length_bucket_order(rows, seed=42) == length_bucket_order(
        rows,
        seed=42,
    )


def test_pair_metrics_compare_vulnerable_scores():
    predictions = [
        {
            "pair_key": "p",
            "gold": 0,
            "side_b_vulnerable_probability": 0.2,
        },
        {
            "pair_key": "p",
            "gold": 1,
            "side_b_vulnerable_probability": 0.8,
        },
    ]

    metrics = pair_metrics(predictions)
    assert metrics["pair_orientation_accuracy"] == 1.0
    assert metrics["independent_both_correct"] == 1.0
