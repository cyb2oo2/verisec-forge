from vrf.pair_annotation import analyze_independent_annotations, build_blinded_packet, select_high_value_pairs


def test_select_high_value_pairs_preserves_unique_pairs():
    rows = [
        {"pair_key": f"pair-{index}", "model_pair_correct": index % 5 != 0, "probability_gap": index / 20, "changed_lines": index}
        for index in range(20)
    ]
    selected = select_high_value_pairs(rows, sample_size=10, seed=7)
    assert len(selected) == 10
    assert len({row["pair_key"] for row in selected}) == 10
    assert {row["selection_stratum"] for row in selected}


def test_blinded_packets_exclude_gold_fields():
    pair = {
        "pair_key": "project|commit|CVE",
        "gold_vulnerable_id": "vuln",
        "selection_stratum": "model_error",
        "rows": [
            {"id": "safe", "code": "safe()", "pair_text": "safe diff"},
            {"id": "vuln", "code": "vuln()", "pair_text": "vuln diff"},
        ],
    }
    packet, answers, mappings = build_blinded_packet([pair], annotator_id="reviewer_1", seed=42)
    assert "gold_vulnerable_id" not in packet[0]
    assert "project" not in packet[0]
    assert answers[0]["vulnerable_side"] == ""
    assert mappings[0]["gold_vulnerable_id"] == "vuln"


def test_agreement_maps_randomized_sides_to_canonical_ids():
    mappings = [
        {"case_id": "a-case", "annotator_id": "a", "pair_key": "pair", "side_a_id": "vuln", "side_b_id": "safe"},
        {"case_id": "b-case", "annotator_id": "b", "pair_key": "pair", "side_a_id": "safe", "side_b_id": "vuln"},
    ]
    rows_a = [{"case_id": "a-case", "annotator_id": "a", "vulnerable_side": "A", "context_sufficient": "yes"}]
    rows_b = [{"case_id": "b-case", "annotator_id": "b", "vulnerable_side": "B", "context_sufficient": "yes"}]
    report = analyze_independent_annotations(rows_a, rows_b, mappings)
    assert report["side_exact_agreement"] == 1.0
    assert report["context_exact_agreement"] == 1.0
    assert report["disagreement_count"] == 0
