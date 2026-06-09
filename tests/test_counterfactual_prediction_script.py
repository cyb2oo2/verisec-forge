from scripts.predict_counterfactual_shortcuts import _softmax_positive


def test_softmax_positive_returns_second_class_probability():
    import torch

    probabilities = _softmax_positive(torch, torch.tensor([[0.0, 0.0], [0.0, 2.0]]))

    assert probabilities[0] == 0.5
    assert probabilities[1] > 0.88
