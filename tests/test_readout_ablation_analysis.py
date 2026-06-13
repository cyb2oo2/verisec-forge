from vrf.readout_ablation_analysis import compare_readouts


def record(
    *,
    post: bool,
    correct: bool = True,
    swap: bool = True,
    robust: bool = False,
):
    return {
        "dataset": "x",
        "pair_key": "p",
        "canonical_correct": correct,
        "post_diff_relation": post,
        "side_swap_relation": swap,
        "robust_success": robust,
        "all_visible": True,
    }


def test_compare_readouts_reports_paired_endpoint_delta():
    result = compare_readouts(
        [record(post=False)],
        [record(post=True)],
        iterations=10,
        seed=1,
    )

    assert (
        result["all_pairs"]["post_diff_relation_delta"]["estimate"]
        == 1.0
    )
    assert (
        result["all_pairs"]["canonical_accuracy_delta"]["estimate"]
        == 0.0
    )
