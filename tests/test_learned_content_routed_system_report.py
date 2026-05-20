from scripts.build_learned_content_routed_system_report import route_predictions, system_metrics


def test_route_predictions_counts_missing_cross_prediction_fallbacks():
    metadata_by_source = {
        "PrimeVul-time": [{"id": "p1", "has_vulnerability": True, "pair_key": "pair-p"}],
        "DeltaSecommits": [{"id": "d1", "has_vulnerability": False, "pair_key": "pair-d"}],
    }
    routing_by_id = {
        "PrimeVul-time::0::p1": "DeltaSecommits",
        "DeltaSecommits::0::d1": "DeltaSecommits",
    }
    expert_delta = {
        "DeltaSecommits::0::d1": {
            "id": "DeltaSecommits::0::d1",
            "gold": 0,
            "pred": 0,
            "pair_key": "DeltaSecommits::pair-d",
            "adapter": "delta",
        }
    }
    matched_predictions = {
        "PrimeVul-time": {
            "PrimeVul-time::0::p1": {
                "id": "PrimeVul-time::0::p1",
                "gold": 1,
                "pred": 1,
                "pair_key": "PrimeVul-time::pair-p",
                "adapter": "matched",
            }
        },
        "DeltaSecommits": expert_delta,
    }

    rows, fallback_counts = route_predictions(
        metadata_by_source=metadata_by_source,
        routing_by_id=routing_by_id,
        prediction_matrix={("DeltaSecommits", "DeltaSecommits"): expert_delta},
        matched_predictions=matched_predictions,
    )

    assert len(rows) == 2
    assert fallback_counts == {"PrimeVul-time->DeltaSecommits": 1}
    assert rows[0]["route"] == "PrimeVul-time->DeltaSecommits fallback:matched-mixed"
    assert rows[1]["route"] == "DeltaSecommits->DeltaSecommits"


def test_system_metrics_reports_balanced_accuracy_and_group_metrics():
    rows = [
        {
            "gold": 1,
            "pred": 1,
            "vuln_probability": 0.9,
            "pair_key": "pair-1",
            "route": "a",
            "adapter": "x",
            "source": "s",
        },
        {
            "gold": 0,
            "pred": 0,
            "vuln_probability": 0.1,
            "pair_key": "pair-1",
            "route": "a",
            "adapter": "x",
            "source": "s",
        },
    ]

    payload = system_metrics("toy", rows)

    assert payload["overall"]["balanced_accuracy"] == 1.0
    assert payload["group_metrics"]["group_all_correct_rate"] == 1.0
    assert payload["route_counts"] == {"a": 2}
