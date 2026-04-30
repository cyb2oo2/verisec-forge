from __future__ import annotations

import pytest

from scripts.evaluate_primevul_bucket_router_calibrated import (
    filter_by_pair_keys,
    parse_thresholds,
    select_threshold,
    split_pair_keys,
)


def test_parse_thresholds_rejects_empty_values() -> None:
    assert parse_thresholds("0.5, 0.8") == [0.5, 0.8]
    with pytest.raises(ValueError):
        parse_thresholds(" , ")


def test_split_pair_keys_keeps_groups_disjoint() -> None:
    rows = [
        {"id": "a1", "pair_key": "a"},
        {"id": "a2", "pair_key": "a"},
        {"id": "b1", "pair_key": "b"},
        {"id": "c1", "pair_key": "c"},
    ]

    split = split_pair_keys(rows, calibration_fraction=0.34, seed=7)

    assert split["calibration"].isdisjoint(split["eval"])
    assert split["calibration"] | split["eval"] == {"a", "b", "c"}
    assert all(row["pair_key"] in split["calibration"] for row in filter_by_pair_keys(rows, split["calibration"]))


def test_select_threshold_uses_requested_selector() -> None:
    rows = [
        {
            "bucket_threshold": 0.7,
            "overall": {"balanced_accuracy": 0.8, "f1": 0.7},
        },
        {
            "bucket_threshold": 0.8,
            "overall": {"balanced_accuracy": 0.79, "f1": 0.75},
        },
    ]

    assert select_threshold(rows, selector="balanced_accuracy")["bucket_threshold"] == 0.7
    assert select_threshold(rows, selector="f1")["bucket_threshold"] == 0.8
    assert select_threshold(rows, selector="f1")["selection_scores"]["tie_break"] == "highest_bucket_threshold"
