from vrf.readout_confirmatory_analysis import compare_confirmatory_models


def record(*, correct: bool, suffix: bool):
    return {
        "dataset": "x",
        "pair_key": "p",
        "canonical_correct": correct,
        "suffix_relations": {
            "confirm_suffix_short_v1": suffix,
            "confirm_suffix_medium_v1": suffix,
            "confirm_suffix_long_v1": suffix,
        },
        "suffix_visible": {
            "confirm_suffix_short_v1": True,
            "confirm_suffix_medium_v1": True,
            "confirm_suffix_long_v1": True,
        },
    }


def test_confirmatory_comparison_applies_noninferiority_rule():
    report = compare_confirmatory_models(
        {7: [record(correct=True, suffix=False)]},
        {7: [record(correct=True, suffix=True)]},
        iterations=10,
        seed=1,
    )

    assert report["success_rule"]["macro_suffix_ci_lower_gt_zero"]
    assert report["success_rule"][
        "canonical_noninferiority_ci_lower_gte_minus_0_02"
    ]
    assert report["pooled_pair_cluster"]["canonical_pairs"] == 1
    assert report["pooled_pair_cluster"]["suffix_visible_pairs"] == 1


def test_confirmatory_suffix_endpoint_excludes_invisible_pairs():
    invisible_control = record(correct=True, suffix=False)
    invisible_candidate = record(correct=False, suffix=True)
    for row in (invisible_control, invisible_candidate):
        row["pair_key"] = "invisible"
        row["suffix_visible"] = {
            name: False for name in row["suffix_visible"]
        }
    visible_control = record(correct=True, suffix=False)
    visible_candidate = record(correct=True, suffix=True)
    visible_control["pair_key"] = "visible"
    visible_candidate["pair_key"] = "visible"

    report = compare_confirmatory_models(
        {7: [invisible_control, visible_control]},
        {7: [invisible_candidate, visible_candidate]},
        iterations=10,
        seed=1,
    )

    pooled = report["pooled_pair_cluster"]
    assert pooled["canonical_pairs"] == 2
    assert pooled["suffix_visible_pairs"] == 1
    assert pooled["macro_suffix_consistency_delta"]["estimate"] == 1.0
