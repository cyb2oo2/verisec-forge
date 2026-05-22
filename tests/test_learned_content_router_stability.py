from scripts.build_learned_content_router_stability_report import build_report
from tests.test_learned_content_router_feature_ablation import tiny_metadata, tiny_predictions


def test_router_stability_reports_seeded_fraction_summaries() -> None:
    metadata = tiny_metadata()
    matched, experts, cross = tiny_predictions(metadata)

    payload = build_report(
        train_metadata_by_source=metadata,
        eval_metadata_by_source=metadata,
        matched_predictions=matched,
        expert_predictions=experts,
        cross_predictions=cross,
        seeds=[1, 2],
        train_fractions=[0.5, 1.0],
        max_features=500,
    )

    assert payload["status"] == "ok"
    assert payload["protocol"]["sampling_unit"] == "pair_key within each source"
    assert sorted(payload["summary_by_train_fraction"]) == ["0.5", "1.0"]
    assert len(payload["runs"]) == 4
    assert payload["summary_by_train_fraction"]["1.0"]["runs"] == 2
    assert "PrimeVul-time" in payload["summary_by_train_fraction"]["1.0"]["per_source"]
