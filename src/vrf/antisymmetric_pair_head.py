"""Reference implementation of the antisymmetric pair-scoring repair head.

This is the *design-stage* numpy reference for the repair objective proposed in
`docs/REPAIR_OBJECTIVE_DESIGN.md`. It is intentionally framework-agnostic and
trains nothing: its job is to make the architectural guarantee and the loss
contract precise and unit-testable before any torch training run (Step 4).

Core idea. A weight-shared joint encoder produces an order-dependent feature
``h(X, Y)`` for "candidate X in the Side-A slot, candidate Y in the Side-B
slot". ``h`` may attend across both candidates and over the diff hunk -- diff
structure is *kept*, not discarded. The score is the antisymmetric readout

    s(A, B) = w . ( h(A, B) - h(B, A) )

so ``s(A, B) == -s(B, A)`` holds *by construction* for any encoder and any
readout weight. Side-swap equivariance is therefore exact and needs no penalty:
``P(A riskier) = sigmoid(s)`` implies ``P(riskier side | swapped) = 1 - P``.

What antisymmetry does NOT give you: polarity invariance. Rendering a diff in
reverse changes ``h`` unless the encoder is fed a canonicalized input or trained
with an explicit invariance loss. Both are provided here as loss terms so the
repair does not silently rely on antisymmetry to fix a problem it cannot fix.
"""

from __future__ import annotations

from typing import Any

import numpy as np

__all__ = [
    "antisymmetric_score",
    "riskier_a_probability",
    "swap_equivariance_residual",
    "pairwise_bce_loss",
    "polarity_invariance_loss",
    "prediction_collapse_penalty",
    "repair_loss",
]


def _as_2d(feat: Any) -> np.ndarray:
    arr = np.asarray(feat, dtype=float)
    return arr[None, :] if arr.ndim == 1 else arr


def antisymmetric_score(feat_ab: Any, feat_ba: Any, weight: Any) -> np.ndarray:
    """Antisymmetric readout ``s = w . (h(A,B) - h(B,A))``.

    ``feat_ab`` / ``feat_ba`` are the shared-encoder features for the two
    candidate orderings; ``weight`` is the linear readout. Returns one score per
    row. ``s(A,B) == -s(B,A)`` holds exactly because swapping the orderings
    negates ``feat_ab - feat_ba``.
    """
    ab = _as_2d(feat_ab)
    ba = _as_2d(feat_ba)
    w = np.asarray(weight, dtype=float)
    return (ab - ba) @ w


def riskier_a_probability(score: Any) -> np.ndarray:
    """``sigmoid(score)`` = probability that Side A is the riskier candidate."""
    s = np.asarray(score, dtype=float)
    return 1.0 / (1.0 + np.exp(-s))


def swap_equivariance_residual(feat_ab: Any, feat_ba: Any, weight: Any) -> np.ndarray:
    """``s(A,B) + s(B,A)`` -- exactly 0 for this head; nonzero for a generic one.

    Kept as a diagnostic/guard so an ablation that replaces the antisymmetric
    readout with an unconstrained head can be measured against the hard
    constraint, and so a training run can assert the constraint never drifts.
    """
    forward = antisymmetric_score(feat_ab, feat_ba, weight)
    reverse = antisymmetric_score(feat_ba, feat_ab, weight)
    return forward + reverse


def pairwise_bce_loss(score: Any, gold_a_riskier: Any) -> float:
    """Binary cross-entropy of ``P(A riskier)`` against the gold side.

    ``gold_a_riskier`` is 1 when Side A is the riskier/vulnerable candidate,
    else 0. This is the pointwise term the invariance/equivariance terms must
    never be allowed to override -- a repair that improves consistency while
    destroying this is a degenerate solution.
    """
    p = np.clip(riskier_a_probability(score), 1e-7, 1 - 1e-7)
    y = np.asarray(gold_a_riskier, dtype=float)
    return float(np.mean(-(y * np.log(p) + (1 - y) * np.log(1 - p))))


def polarity_invariance_loss(score_canonical: Any, score_polarity_flipped: Any) -> float:
    """Squared score gap between a pair and its reverse-diff rendering.

    Same candidate ordering and gold; only the diff hunk polarity differs. A
    content-tracking model should give the same score, so this is zero when the
    encoder is polarity-invariant and positive otherwise. This is the term that
    actually targets the measured failure (`reports/POLARITY_GOLD_CONFOUND.md`);
    antisymmetry alone does not.
    """
    a = np.asarray(score_canonical, dtype=float)
    b = np.asarray(score_polarity_flipped, dtype=float)
    return float(np.mean((a - b) ** 2))


def prediction_collapse_penalty(
    probs: Any, *, min_variance: float = 0.02
) -> float:
    """Guard against the degenerate constant predictor.

    Invariance and violation-rate can both be driven to their optimum by a model
    that always predicts one side. This penalizes (a) a batch marginal far from
    0.5 and (b) near-zero prediction variance, so a collapse is visible in the
    loss. It is a guard, not a fix: per-class accuracy must still be reported
    (see `docs/EVIDENCE_HIERARCHY.md`).
    """
    p = np.asarray(probs, dtype=float)
    marginal = float((np.mean(p) - 0.5) ** 2)
    variance_shortfall = float(max(0.0, min_variance - np.var(p)))
    return marginal + variance_shortfall


def repair_loss(
    *,
    score: Any,
    gold_a_riskier: Any,
    score_canonical: Any | None = None,
    score_polarity_flipped: Any | None = None,
    lambda_polarity: float = 1.0,
    lambda_collapse: float = 0.1,
) -> dict[str, float]:
    """Combine the pointwise, polarity-invariance, and collapse-guard terms.

    Swap-equivariance is not a term because the antisymmetric head enforces it
    exactly (see ``swap_equivariance_residual``). Returns each component and the
    weighted total so training logs can show the pointwise term is preserved
    while the invariance term falls -- the signature of a real repair rather than
    a consistency win bought with accuracy.
    """
    ce = pairwise_bce_loss(score, gold_a_riskier)
    collapse = prediction_collapse_penalty(riskier_a_probability(score))
    polarity = 0.0
    if score_canonical is not None and score_polarity_flipped is not None:
        polarity = polarity_invariance_loss(score_canonical, score_polarity_flipped)
    total = ce + lambda_polarity * polarity + lambda_collapse * collapse
    return {
        "total": total,
        "pointwise_bce": ce,
        "polarity_invariance": polarity,
        "collapse_penalty": collapse,
    }
