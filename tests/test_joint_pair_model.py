from vrf.joint_pair_model import build_ordered_pair_records, summarize_ordered_pairs


def test_ordered_pair_records_balance_position_without_using_gold_slot():
    rows = []
    for pair_key in ("a", "b", "c", "d"):
        rows.extend(
            [
                {"pair_key": pair_key, "label": 0, "text": f"{pair_key}-safe"},
                {"pair_key": pair_key, "label": 1, "text": f"{pair_key}-vulnerable"},
            ]
        )
    records = build_ordered_pair_records(rows)
    assert len(records) == 4
    assert all(record[f"text_{record['label']}"].endswith("-vulnerable") for record in records)
    summary = summarize_ordered_pairs(records)
    assert summary["target_0"] > 0
    assert summary["target_1"] > 0


def test_incomplete_pairs_are_skipped():
    records = build_ordered_pair_records([{"pair_key": "x", "label": 1, "text": "vulnerable"}])
    assert records == []
