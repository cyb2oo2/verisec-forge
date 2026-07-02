from vrf.polarity_gold_confound import (
    eval_set_gold_side_balance,
    model_shortcut_agreement,
    net_polarity,
    orientation_balance,
    polarity_gold_correlation,
    source_pair_cleanliness,
)

ADDED = "--- Side A\n+++ Side B\n@@\n context();\n+ guard();\n"
REMOVED = "--- Side A\n+++ Side B\n@@\n context();\n- guard();\n"
BALANCED = "--- Side A\n+++ Side B\n@@\n-old();\n+new();\n"


def test_net_polarity_ignores_file_headers():
    assert net_polarity(ADDED) == "net_added"
    assert net_polarity(REMOVED) == "net_removed"
    assert net_polarity(BALANCED) == "balanced"


def test_orientation_balance_detects_augmentation():
    rows = [
        {"source_pair_key": "p1", "orientation": "observed", "vulnerable_side": "A"},
        {"source_pair_key": "p1", "orientation": "synthetic_reverse", "vulnerable_side": "B"},
        {"source_pair_key": "p2", "orientation": "observed", "vulnerable_side": "B"},
        {"source_pair_key": "p2", "orientation": "synthetic_reverse", "vulnerable_side": "A"},
    ]
    summary = orientation_balance(rows)
    assert summary["frac_vulnerable_side_a"] == 0.5
    assert summary["source_pairs"] == 2
    assert summary["source_pairs_multi_orientation"] == 2


def test_polarity_gold_correlation_shortcut_accuracy():
    rows = [
        {"text": ADDED, "gold_riskier_side": "A"},  # shortcut correct
        {"text": ADDED, "gold_riskier_side": "B"},  # shortcut wrong
        {"text": REMOVED, "gold_riskier_side": "B"},  # shortcut correct
        {"text": BALANCED, "gold_riskier_side": "A"},  # undecided, excluded
    ]
    corr = polarity_gold_correlation(rows)
    assert corr["shortcut_decided_rows"] == 3
    assert abs(corr["shortcut_accuracy"] - 2 / 3) < 1e-9
    assert corr["p_gold_a_given_net_added"] == 0.5


def test_model_shortcut_agreement_excludes_balanced_and_missing():
    rows = [
        {"id": "1", "text": ADDED},     # shortcut says A
        {"id": "2", "text": REMOVED},   # shortcut says B
        {"id": "3", "text": BALANCED},  # excluded (undecided)
    ]
    predictions = {
        "1": {"predicted_riskier_side": "A"},  # agrees
        "2": {"predicted_riskier_side": "A"},  # disagrees
        # id 3 has no prediction anyway
    }
    result = model_shortcut_agreement(rows, predictions)
    assert result["n"] == 2
    assert result["agreement"] == 0.5


def test_source_pair_cleanliness_detects_dirty_and_wrong_size_groups():
    rows = [
        # clean pair: one vulnerable, one secure
        {"pair_key": "p1", "has_vulnerability": True},
        {"pair_key": "p1", "has_vulnerability": False},
        # dirty pair: both vulnerable
        {"pair_key": "p2", "has_vulnerability": True},
        {"pair_key": "p2", "has_vulnerability": True},
        # wrong-size group: singleton, excluded from pair counts
        {"pair_key": "p3", "has_vulnerability": True},
    ]
    result = source_pair_cleanliness(rows)
    assert result["total_rows"] == 5
    assert result["total_pair_keys"] == 3
    assert result["two_row_pair_groups"] == 2
    assert result["clean_one_vulnerable_one_secure_pairs"] == 1
    assert result["dirty_pair_groups"] == 1


def test_eval_set_gold_side_balance_computes_fraction():
    rows = [
        {"gold_riskier_side": "A"},
        {"gold_riskier_side": "A"},
        {"gold_riskier_side": "B"},
        {"gold_riskier_side": "A_RISKIER"},  # normalizes to A
    ]
    result = eval_set_gold_side_balance(rows)
    assert result["canonical_rows"] == 4
    assert result["gold_side_counts"] == {"A": 3, "B": 1}
    assert result["frac_gold_riskier_side_a"] == 0.75


def test_eval_set_gold_side_balance_empty_rows():
    result = eval_set_gold_side_balance([])
    assert result["canonical_rows"] == 0
    assert result["frac_gold_riskier_side_a"] is None
