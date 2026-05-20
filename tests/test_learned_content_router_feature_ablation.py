from scripts.build_learned_content_router_feature_ablation_report import build_report


def pred(row_id: str, source: str, pair_key: str, gold: int, pred_label: int, prob: float, adapter: str) -> dict:
    return {
        "id": row_id,
        "source": source,
        "adapter": adapter,
        "gold": gold,
        "pred": pred_label,
        "vuln_probability": prob,
        "pair_key": f"{source}::{pair_key}",
    }


def tiny_metadata() -> dict[str, list[dict]]:
    return {
        "PrimeVul-time": [{"id": "p1", "pair_key": "p1", "has_vulnerability": True, "pair_text": "Unified diff:\n+linux kfree struct"}],
        "DeltaSecommits": [
            {"id": "d1", "pair_key": "d1", "has_vulnerability": True, "pair_text": "Unified diff:\n+tensorflow OP_REQUIRES tensor"}
        ],
        "PatchEval": [{"id": "e1", "pair_key": "e1", "has_vulnerability": False, "pair_text": "Unified diff:\n+func handle(err error)"}],
    }


def tiny_predictions(metadata: dict[str, list[dict]]) -> tuple[dict, dict, dict]:
    matched = {}
    experts = {}
    cross = {}
    for source, rows in metadata.items():
        row = rows[0]
        row_id = f"{source}::0::{row['id']}"
        gold = int(row.get("has_vulnerability", False))
        matched[source] = {row_id: pred(row_id, source, row["pair_key"], gold, gold, 0.8, "matched")}
        experts[source] = {row_id: pred(row_id, source, row["pair_key"], gold, gold, 0.9, "expert")}
    for source, rows in metadata.items():
        for routed in metadata:
            if source == routed:
                continue
            row = rows[0]
            row_id = f"{source}::0::{row['id']}"
            gold = int(row.get("has_vulnerability", False))
            cross[(source, routed)] = {row_id: pred(row_id, source, row["pair_key"], gold, gold, 0.7, "cross")}
    return matched, experts, cross


def test_feature_ablation_builds_multiple_router_views() -> None:
    metadata = tiny_metadata()
    matched, experts, cross = tiny_predictions(metadata)

    payload = build_report(
        train_metadata_by_source=metadata,
        eval_metadata_by_source=metadata,
        matched_predictions=matched,
        expert_predictions=experts,
        cross_predictions=cross,
        feature_modes=["char_3_5", "token_1_2", "diff_line_markers"],
        max_features=500,
    )

    assert payload["status"] == "ok"
    assert [row["feature_mode"] for row in payload["feature_results"]] == ["char_3_5", "token_1_2", "diff_line_markers"]
    assert all(row["routing_metrics"]["row_count"] == 3 for row in payload["feature_results"])
