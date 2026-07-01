import pytest

torch = pytest.importorskip("torch")

from vrf.antisymmetric_pair_head_torch import (  # noqa: E402
    AntisymmetricPairHead,
    repair_loss_torch,
)


def test_torch_head_is_exactly_antisymmetric():
    torch.manual_seed(0)
    head = AntisymmetricPairHead(hidden_size=8)
    h_ab = torch.randn(16, 8)
    h_ba = torch.randn(16, 8)
    forward = head(h_ab, h_ba)
    reverse = head(h_ba, h_ab)
    assert torch.allclose(forward, -reverse, atol=1e-6)


def test_repair_loss_backprops_and_reports_components():
    torch.manual_seed(1)
    head = AntisymmetricPairHead(hidden_size=4)
    h_ab = torch.randn(12, 4, requires_grad=True)
    h_ba = torch.randn(12, 4)
    score = head(h_ab, h_ba)
    gold = (score.detach() > 0).long()
    flipped = score + 0.5
    out = repair_loss_torch(
        score=score,
        gold_a_riskier=gold,
        score_canonical=score,
        score_polarity_flipped=flipped,
    )
    assert set(out) == {"total", "pointwise_bce", "polarity_invariance", "collapse_penalty"}
    assert out["polarity_invariance"].item() > 0.0
    out["total"].backward()
    assert h_ab.grad is not None and torch.isfinite(h_ab.grad).all()


def test_polarity_term_zero_when_renderings_match():
    torch.manual_seed(2)
    score = torch.randn(10)
    gold = (score > 0).long()
    out = repair_loss_torch(
        score=score,
        gold_a_riskier=gold,
        score_canonical=score,
        score_polarity_flipped=score.clone(),
    )
    assert out["polarity_invariance"].item() == pytest.approx(0.0)
