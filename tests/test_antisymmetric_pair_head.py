import numpy as np

from vrf.antisymmetric_pair_head import (
    antisymmetric_score,
    pairwise_bce_loss,
    polarity_invariance_loss,
    prediction_collapse_penalty,
    repair_loss,
    riskier_a_probability,
    swap_equivariance_residual,
)


def test_score_is_exactly_antisymmetric_for_random_features():
    rng = np.random.default_rng(0)
    for _ in range(50):
        d = int(rng.integers(1, 8))
        h_ab = rng.normal(size=d)
        h_ba = rng.normal(size=d)
        w = rng.normal(size=d)
        forward = antisymmetric_score(h_ab, h_ba, w)
        reverse = antisymmetric_score(h_ba, h_ab, w)
        assert np.allclose(forward, -reverse)


def test_swap_equivariance_residual_is_zero_by_construction():
    rng = np.random.default_rng(1)
    h_ab = rng.normal(size=(16, 4))
    h_ba = rng.normal(size=(16, 4))
    w = rng.normal(size=4)
    residual = swap_equivariance_residual(h_ab, h_ba, w)
    assert np.allclose(residual, 0.0, atol=1e-12)


def test_probability_swap_equivariance():
    # P(riskier side | swapped ordering) == 1 - P(A riskier).
    rng = np.random.default_rng(2)
    h_ab = rng.normal(size=(10, 5))
    h_ba = rng.normal(size=(10, 5))
    w = rng.normal(size=5)
    p_forward = riskier_a_probability(antisymmetric_score(h_ab, h_ba, w))
    p_reverse = riskier_a_probability(antisymmetric_score(h_ba, h_ab, w))
    assert np.allclose(p_reverse, 1.0 - p_forward)


def test_polarity_invariance_loss_zero_when_scores_match():
    s = np.array([0.3, -1.2, 2.0])
    assert polarity_invariance_loss(s, s) == 0.0
    assert polarity_invariance_loss(s, s + 0.5) > 0.0


def test_collapse_penalty_flags_constant_predictor():
    constant = np.full(32, 0.9)  # always predicts A, no spread
    spread = np.concatenate([np.full(16, 0.2), np.full(16, 0.8)])  # balanced
    assert prediction_collapse_penalty(constant) > prediction_collapse_penalty(spread)


def test_pairwise_bce_rewards_correct_side():
    # Confident-correct should beat confident-wrong.
    correct = pairwise_bce_loss(np.array([4.0]), np.array([1.0]))
    wrong = pairwise_bce_loss(np.array([4.0]), np.array([0.0]))
    assert correct < wrong


def test_repair_loss_reports_components_and_preserves_pointwise():
    rng = np.random.default_rng(3)
    h_ab = rng.normal(size=(8, 3))
    h_ba = rng.normal(size=(8, 3))
    w = rng.normal(size=3)
    score = antisymmetric_score(h_ab, h_ba, w)
    gold = (score > 0).astype(float)  # perfectly separable -> low CE
    flipped = score + rng.normal(scale=0.5, size=score.shape)
    out = repair_loss(
        score=score,
        gold_a_riskier=gold,
        score_canonical=score,
        score_polarity_flipped=flipped,
        lambda_polarity=1.0,
    )
    assert set(out) == {
        "total",
        "pointwise_bce",
        "polarity_invariance",
        "collapse_penalty",
    }
    assert out["polarity_invariance"] > 0.0
    # total must include the polarity term on top of the pointwise term
    assert out["total"] >= out["pointwise_bce"]
