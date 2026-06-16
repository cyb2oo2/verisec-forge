import torch

from vrf.frozen_readout_control import (
    complete_pair_indices,
    margin_matched_comparison,
    normalize_hf_model_source,
    pairwise_head_loss,
    pool_frozen_representations,
    state_dict_sha256,
)


def test_pool_frozen_representations_uses_matched_hidden_states():
    hidden = torch.tensor(
        [
            [
                [1.0, 0.0],
                [2.0, 0.0],
                [9.0, 0.0],
            ]
        ]
    )
    pooled, fallback = pool_frozen_representations(
        hidden,
        input_ids=torch.tensor([[4, 5, 0]]),
        attention_mask=torch.tensor([[1, 1, 0]]),
        pooling_mask=torch.tensor([[0, 1, 0]]),
        pad_token_id=0,
    )

    assert pooled["terminal"].tolist() == [[2.0, 0.0]]
    assert pooled["mean"].tolist() == [[1.5, 0.0]]
    assert pooled["changed_hunk"].tolist() == [[2.0, 0.0]]
    assert fallback.tolist() == [False]


def test_normalize_hf_model_source_extracts_id_and_revision():
    result = normalize_hf_model_source(
        "C:\\cache\\models--Qwen--Coder\\snapshots\\abc123"
    )

    assert result == {"model_id": "Qwen/Coder", "revision": "abc123"}


def test_changed_hunk_falls_back_to_visible_mean():
    hidden = torch.tensor([[[1.0], [3.0]]])
    pooled, fallback = pool_frozen_representations(
        hidden,
        input_ids=torch.tensor([[4, 5]]),
        attention_mask=torch.tensor([[1, 1]]),
        pooling_mask=torch.tensor([[0, 0]]),
        pad_token_id=0,
    )

    assert pooled["changed_hunk"].tolist() == [[2.0]]
    assert fallback.tolist() == [True]


def test_complete_pair_indices_orders_label_zero_then_one():
    metadata = [
        {"pair_key": "p", "label": 1},
        {"pair_key": "p", "label": 0},
        {"pair_key": "incomplete", "label": 1},
    ]

    assert complete_pair_indices(metadata) == [(1, 0)]


def test_pairwise_head_loss_rewards_correct_orientation():
    good = torch.tensor([[[4.0, 0.0], [0.0, 4.0]]])
    bad = torch.tensor([[[0.0, 4.0], [4.0, 0.0]]])

    good_loss, _ = pairwise_head_loss(
        good,
        margin=0.5,
        margin_weight=0.5,
        complement_weight=0.1,
    )
    bad_loss, _ = pairwise_head_loss(
        bad,
        margin=0.5,
        margin_weight=0.5,
        complement_weight=0.1,
    )

    assert good_loss < bad_loss


def test_state_dict_hash_is_stable():
    state = {"weight": torch.tensor([[1.0, 2.0]])}
    assert state_dict_sha256(state) == state_dict_sha256(state)


def test_margin_matched_comparison_filters_confidence_gap():
    def row(pair_key, margin, suffix):
        return {
            "dataset": "x",
            "pair_key": pair_key,
            "canonical_margin": margin,
            "suffix_relations": {"s": suffix},
            "suffix_visible": {"s": True},
        }

    report = margin_matched_comparison(
        [row("kept", 0.2, False), row("dropped", 0.1, False)],
        [row("kept", 0.23, True), row("dropped", 0.5, True)],
        tolerance=0.05,
        iterations=10,
        seed=1,
    )

    assert report["pairs"] == 1
    assert report["coverage"] == 0.5
    assert report["macro_suffix_consistency_delta"]["estimate"] == 1.0
