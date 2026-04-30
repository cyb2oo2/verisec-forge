from __future__ import annotations

from scripts.evaluate_primevul_bucket_router import (
    compute_binary_metrics,
    route_predictions,
    summarize_by_bucket,
)


def test_bucket_router_uses_specialist_only_for_target_bucket() -> None:
    long_diff = "\n".join(["+x"] * 27)
    rows = [
        {
            "id": "large",
            "has_vulnerability": True,
            "pair_text": f"Unified diff:\n{long_diff}",
        },
        {
            "id": "small",
            "has_vulnerability": False,
            "pair_text": "Unified diff:\n-old\n+new\n",
        },
    ]
    default_predictions = {
        "large": {"id": "large", "vuln_probability": 0.1},
        "small": {"id": "small", "vuln_probability": 0.1},
    }
    bucket_predictions = {
        "large": {"id": "large", "vuln_probability": 0.9},
        "small": {"id": "small", "vuln_probability": 0.9},
    }

    routed, route_counts = route_predictions(
        rows,
        default_predictions,
        bucket_predictions,
        bucket="26+",
        default_threshold=0.5,
        bucket_threshold=0.8,
    )

    assert route_counts == {"default": 1, "bucket": 1}
    assert routed[0]["route"] == "bucket"
    assert routed[0]["pred"] == 1
    assert routed[0]["changed_line_bucket"] == "26+"
    assert routed[1]["route"] == "default"
    assert routed[1]["pred"] == 0
    assert routed[1]["changed_line_bucket"] == "00-02"
    assert compute_binary_metrics(routed)["balanced_accuracy"] == 1.0
    assert summarize_by_bucket(routed)["26+"]["tp"] == 1
