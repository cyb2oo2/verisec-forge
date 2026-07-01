"""Torch port of the antisymmetric pair head + repair loss (Step 4 training path).

Mirrors the numpy reference in `antisymmetric_pair_head.py` on the real tensor
path so the training run in Step 4 uses a unit-tested loss. The module is
import-light: torch is imported lazily inside the functions so the rest of the
package (and CI's torch-free smoke path) is unaffected.

Wiring into `scripts/train_joint_pairwise_classifier.py`: replace the linear
head with `AntisymmetricPairHead` over the shared encoder's pooled feature for
the two candidate orderings, and use `repair_loss_torch` in place of the plain
BCE. See `docs/REPAIR_OBJECTIVE_DESIGN.md`.
"""

from __future__ import annotations

from typing import Any

__all__ = ["AntisymmetricPairHead", "repair_loss_torch"]


def _torch():
    import torch  # local import keeps package import torch-free

    return torch


class _HeadFactory:
    """Deferred nn.Module definition so importing this file needs no torch."""

    _cls: Any = None

    @classmethod
    def get(cls) -> Any:
        if cls._cls is not None:
            return cls._cls
        torch = _torch()
        nn = torch.nn

        class AntisymmetricPairHead(nn.Module):
            """Score s(A,B) = w . (h(A,B) - h(B,A)); s(A,B) = -s(B,A) exactly.

            ``forward`` takes the shared encoder features for the two candidate
            orderings, each ``(batch, hidden)``, and returns ``(batch,)`` logits
            for "Side A is riskier". Antisymmetry holds by construction: the same
            linear readout applied to ``h_ab - h_ba``.
            """

            def __init__(self, hidden_size: int):
                super().__init__()
                self.readout = nn.Linear(hidden_size, 1, bias=False)

            def forward(self, feat_ab, feat_ba):
                return self.readout(feat_ab - feat_ba).squeeze(-1)

        cls._cls = AntisymmetricPairHead
        return cls._cls


def AntisymmetricPairHead(hidden_size: int):  # noqa: N802 (factory facade)
    """Instantiate the antisymmetric head (torch required at call time)."""
    return _HeadFactory.get()(hidden_size)


def repair_loss_torch(
    *,
    score,
    gold_a_riskier,
    score_canonical=None,
    score_polarity_flipped=None,
    lambda_polarity: float = 1.0,
    lambda_collapse: float = 0.1,
    min_variance: float = 0.02,
) -> dict[str, Any]:
    """Differentiable repair loss matching the numpy reference's contract.

    Returns a dict of scalar tensors: ``total`` (backprop this), plus the
    ``pointwise_bce``, ``polarity_invariance``, and ``collapse_penalty``
    components for logging. Swap-equivariance is architectural (the head), so it
    is not a term here.
    """
    torch = _torch()
    bce = torch.nn.functional.binary_cross_entropy_with_logits(
        score, gold_a_riskier.float()
    )
    probs = torch.sigmoid(score)
    marginal = (probs.mean() - 0.5) ** 2
    variance_shortfall = torch.clamp(min_variance - probs.var(unbiased=False), min=0.0)
    collapse = marginal + variance_shortfall

    if score_canonical is not None and score_polarity_flipped is not None:
        polarity = torch.mean((score_canonical - score_polarity_flipped) ** 2)
    else:
        polarity = torch.zeros((), dtype=bce.dtype, device=bce.device)

    total = bce + lambda_polarity * polarity + lambda_collapse * collapse
    return {
        "total": total,
        "pointwise_bce": bce.detach(),
        "polarity_invariance": polarity.detach(),
        "collapse_penalty": collapse.detach(),
    }
