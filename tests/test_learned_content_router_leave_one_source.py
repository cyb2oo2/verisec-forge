from scripts.build_learned_content_router_leave_one_source_report import build_report, pair_route_distribution


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


def test_pair_route_distribution_uses_pair_majority() -> None:
    rows = [
        {"pair_key": "p1", "predicted_source": "DeltaSecommits"},
        {"pair_key": "p1", "predicted_source": "DeltaSecommits"},
        {"pair_key": "p2", "predicted_source": "PatchEval"},
    ]

    assert pair_route_distribution(rows) == {"DeltaSecommits": 1, "PatchEval": 1}


def test_leave_one_source_report_tracks_open_set_boundary() -> None:
    sources = ["PrimeVul-time", "DeltaSecommits", "PatchEval"]
    train_metadata = {
        "PrimeVul-time": [{"id": "pt", "pair_key": "pt", "pair_text": "Unified diff:\n+linux kfree struct"}],
        "DeltaSecommits": [{"id": "dt", "pair_key": "dt", "pair_text": "Unified diff:\n+tensorflow OP_REQUIRES tensor"}],
        "PatchEval": [{"id": "et", "pair_key": "et", "pair_text": "Unified diff:\n+func handle(err error)"}],
    }
    eval_metadata = {
        "PrimeVul-time": [{"id": "pe", "pair_key": "pe", "has_vulnerability": True, "pair_text": "Unified diff:\n+linux kfree struct"}],
        "DeltaSecommits": [
            {"id": "de", "pair_key": "de", "has_vulnerability": True, "pair_text": "Unified diff:\n+tensorflow OP_REQUIRES tensor"}
        ],
        "PatchEval": [{"id": "ee", "pair_key": "ee", "has_vulnerability": False, "pair_text": "Unified diff:\n+func handle(err error)"}],
    }
    matched = {
        source: {
            f"{source}::0::{rows[0]['id']}": pred(f"{source}::0::{rows[0]['id']}", source, rows[0]["pair_key"], int(rows[0].get("has_vulnerability", False)), 1, 0.9, "matched")
        }
        for source, rows in eval_metadata.items()
    }
    experts = {
        source: {
            f"{source}::0::{rows[0]['id']}": pred(f"{source}::0::{rows[0]['id']}", source, rows[0]["pair_key"], int(rows[0].get("has_vulnerability", False)), int(rows[0].get("has_vulnerability", False)), 0.8, "expert")
        }
        for source, rows in eval_metadata.items()
    }
    cross = {}
    for source in sources:
        for routed in sources:
            if source == routed:
                continue
            row = eval_metadata[source][0]
            row_id = f"{source}::0::{row['id']}"
            cross[(source, routed)] = {
                row_id: pred(row_id, source, row["pair_key"], int(row.get("has_vulnerability", False)), int(row.get("has_vulnerability", False)), 0.7, f"{routed} cross")
            }

    payload = build_report(
        train_metadata_by_source=train_metadata,
        eval_metadata_by_source=eval_metadata,
        matched_predictions=matched,
        expert_predictions=experts,
        cross_predictions=cross,
        max_features=500,
    )

    assert payload["status"] == "ok"
    assert len(payload["heldout_results"]) == 3
    assert all(sum(result["fallback_counts"].values()) == 0 for result in payload["heldout_results"])
