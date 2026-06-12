import pytest

from scripts.predict_veripatch_rr import prediction_from_probability


def test_prediction_probability_maps_classifier_label_one_to_side_b():
    predicted_b = prediction_from_probability(
        "row-b", 0.8, model_id="demo"
    )
    predicted_a = prediction_from_probability(
        "row-a", 0.2, model_id="demo"
    )

    assert predicted_b["predicted_riskier_side"] == "B"
    assert predicted_b["probability_a"] == pytest.approx(0.2)
    assert predicted_a["predicted_riskier_side"] == "A"
    assert predicted_a["probability_a"] == pytest.approx(0.8)
    assert predicted_a["supports_abstention"] is False
