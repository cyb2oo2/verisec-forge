from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_content_source_router_report import routing_metrics
from scripts.build_learned_content_routed_system_report import (
    coupled_prediction_rows,
    final_prediction_rows,
    normalize_metadata,
    read_jsonl,
    route_predictions,
    system_metrics,
)
from scripts.build_learned_content_source_router_report import SOURCES, examples, predict_one, train_nb


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = ROOT / path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def metric_delta(candidate: dict[str, Any], baseline: dict[str, Any], section: str, metric: str) -> float:
    return round(float(candidate[section][metric]) - float(baseline[section][metric]), 4)


def pair_route_distribution(route_rows: list[dict[str, Any]]) -> dict[str, int]:
    pair_votes: dict[str, Counter[str]] = {}
    for row in route_rows:
        pair_votes.setdefault(str(row["pair_key"]), Counter())
        pair_votes[str(row["pair_key"])][str(row["predicted_source"])] += 1
    distribution: Counter[str] = Counter()
    for votes in pair_votes.values():
        predicted_source, _count = votes.most_common(1)[0]
        distribution[predicted_source] += 1
    return dict(sorted(distribution.items()))


def route_eval_rows(
    *,
    model: dict[str, Any],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    routing_by_key: dict[str, str] = {}
    route_rows: list[dict[str, Any]] = []
    for source, rows in eval_metadata_by_source.items():
        for item in normalize_metadata(source, rows):
            text = examples({source: [item["metadata"]]}, mode="diff_body")[0]["text"]
            predicted_source = predict_one(model, text)
            routing_by_key[item["row_key"]] = predicted_source
            route_rows.append(
                {
                    "true_source": source,
                    "predicted_source": predicted_source,
                    "id": item["id"],
                    "row_key": item["row_key"],
                    "pair_key": str(item["metadata"].get("pair_key") or item["metadata"].get("id")),
                }
            )
    return routing_by_key, route_rows


def prediction_matrix_from_artifacts(
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    prediction_matrix = {(source, source): rows for source, rows in expert_predictions.items()}
    prediction_matrix.update(cross_predictions)
    return prediction_matrix


def build_default_artifacts(
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    matched_predictions = {
        "PrimeVul-time": final_prediction_rows(
            source="PrimeVul-time",
            metadata_rows=eval_metadata_by_source["PrimeVul-time"],
            prediction_path="outputs/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_pair_coupled_v1_predictions.jsonl",
            adapter="matched-mixed",
        ),
        "DeltaSecommits": coupled_prediction_rows(
            source="DeltaSecommits",
            metadata_rows=eval_metadata_by_source["DeltaSecommits"],
            prediction_path="outputs/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_delta_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="matched-mixed",
        ),
        "PatchEval": coupled_prediction_rows(
            source="PatchEval",
            metadata_rows=eval_metadata_by_source["PatchEval"],
            prediction_path="outputs/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_patcheval_raw_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="matched-mixed",
        ),
    }
    expert_predictions = {
        "PrimeVul-time": final_prediction_rows(
            source="PrimeVul-time",
            metadata_rows=eval_metadata_by_source["PrimeVul-time"],
            prediction_path="outputs/secure_code_primevul_time_disjoint_pair_coupled_direct_train_v1_predictions.jsonl",
            adapter="primevul-time expert",
        ),
        "DeltaSecommits": coupled_prediction_rows(
            source="DeltaSecommits",
            metadata_rows=eval_metadata_by_source["DeltaSecommits"],
            prediction_path="outputs/secure_code_deltasecommits_cls_qwen15bcoder_lora_pair_diff_cpp_v1_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="deltasecommits expert",
        ),
        "PatchEval": coupled_prediction_rows(
            source="PatchEval",
            metadata_rows=eval_metadata_by_source["PatchEval"],
            prediction_path="outputs/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_v1_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="patcheval expert",
        ),
    }
    cross_predictions = {
        ("PrimeVul-time", "DeltaSecommits"): coupled_prediction_rows(
            source="PrimeVul-time",
            metadata_rows=eval_metadata_by_source["PrimeVul-time"],
            prediction_path="outputs/secure_code_deltasecommits_adapter_primevul_time_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="deltasecommits expert cross-source",
        ),
        ("DeltaSecommits", "PrimeVul-time"): coupled_prediction_rows(
            source="DeltaSecommits",
            metadata_rows=eval_metadata_by_source["DeltaSecommits"],
            prediction_path="outputs/secure_code_deltasecommits_primevul_time_checkpoint_zero_shot_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="primevul-time checkpoint zero-shot",
            align_by_id=True,
        ),
        ("PrimeVul-time", "PatchEval"): coupled_prediction_rows(
            source="PrimeVul-time",
            metadata_rows=eval_metadata_by_source["PrimeVul-time"],
            prediction_path="outputs/secure_code_patcheval_adapter_primevul_time_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="patcheval expert cross-source",
        ),
        ("DeltaSecommits", "PatchEval"): coupled_prediction_rows(
            source="DeltaSecommits",
            metadata_rows=eval_metadata_by_source["DeltaSecommits"],
            prediction_path="outputs/secure_code_patcheval_adapter_delta_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="patcheval expert cross-source",
        ),
        ("PatchEval", "PrimeVul-time"): coupled_prediction_rows(
            source="PatchEval",
            metadata_rows=eval_metadata_by_source["PatchEval"],
            prediction_path="outputs/secure_code_primevul_time_adapter_patcheval_eval_predictions.jsonl",
            threshold=0.6,
            margin=0.02,
            adapter="primevul-time expert cross-source",
        ),
        ("PatchEval", "DeltaSecommits"): coupled_prediction_rows(
            source="PatchEval",
            metadata_rows=eval_metadata_by_source["PatchEval"],
            prediction_path="outputs/secure_code_deltasecommits_adapter_patcheval_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="deltasecommits expert cross-source",
        ),
    }
    return {
        "train_metadata_by_source": train_metadata_by_source,
        "eval_metadata_by_source": eval_metadata_by_source,
        "matched_predictions": matched_predictions,
        "expert_predictions": expert_predictions,
        "cross_predictions": cross_predictions,
    }


def evaluate_heldout_source(
    *,
    heldout_source: str,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    max_features: int,
) -> dict[str, Any]:
    train_sources = [source for source in SOURCES if source != heldout_source]
    train_subset = {source: train_metadata_by_source[source] for source in train_sources}
    heldout_eval = {heldout_source: eval_metadata_by_source[heldout_source]}
    seen_eval = {source: eval_metadata_by_source[source] for source in train_sources}
    model = train_nb(examples(train_subset, mode="diff_body"), max_features=max_features, classes=train_sources)

    heldout_routing_by_key, heldout_route_rows = route_eval_rows(model=model, eval_metadata_by_source=heldout_eval)
    _seen_routing_by_key, seen_route_rows = route_eval_rows(model=model, eval_metadata_by_source=seen_eval)
    prediction_matrix = prediction_matrix_from_artifacts(expert_predictions, cross_predictions)
    routed_rows, fallback_counts = route_predictions(
        metadata_by_source=heldout_eval,
        routing_by_id=heldout_routing_by_key,
        prediction_matrix=prediction_matrix,
        matched_predictions=matched_predictions,
    )
    single_system = system_metrics("heldout single matched-mixed checkpoint", list(matched_predictions[heldout_source].values()))
    oracle_system = system_metrics("heldout source-specific expert", list(expert_predictions[heldout_source].values()))
    routed_system = system_metrics("heldout leave-one-source routed existing experts", routed_rows)
    return {
        "heldout_source": heldout_source,
        "train_sources": train_sources,
        "train_rows": {source: len(train_metadata_by_source[source]) for source in train_sources},
        "heldout_eval_rows": len(eval_metadata_by_source[heldout_source]),
        "heldout_eval_pair_groups": len({str(row.get("pair_key") or row.get("id")) for row in eval_metadata_by_source[heldout_source]}),
        "seen_source_routing_metrics": routing_metrics(seen_route_rows),
        "heldout_route_distribution": dict(sorted(Counter(row["predicted_source"] for row in heldout_route_rows).items())),
        "heldout_pair_route_distribution": pair_route_distribution(heldout_route_rows),
        "fallback_counts": fallback_counts,
        "systems": [
            single_system,
            oracle_system,
            routed_system,
        ],
        "deltas": {
            "routed_minus_single": {
                "balanced_accuracy": metric_delta(routed_system, single_system, "overall", "balanced_accuracy"),
                "group_all_correct_rate": metric_delta(routed_system, single_system, "group_metrics", "group_all_correct_rate"),
                "orientation_accuracy": metric_delta(routed_system, single_system, "group_metrics", "orientation_accuracy"),
            },
            "routed_minus_oracle": {
                "balanced_accuracy": metric_delta(routed_system, oracle_system, "overall", "balanced_accuracy"),
                "group_all_correct_rate": metric_delta(routed_system, oracle_system, "group_metrics", "group_all_correct_rate"),
                "orientation_accuracy": metric_delta(routed_system, oracle_system, "group_metrics", "orientation_accuracy"),
            },
        },
    }


def build_report(
    *,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    max_features: int = 50000,
) -> dict[str, Any]:
    results = [
        evaluate_heldout_source(
            heldout_source=source,
            train_metadata_by_source=train_metadata_by_source,
            eval_metadata_by_source=eval_metadata_by_source,
            matched_predictions=matched_predictions,
            expert_predictions=expert_predictions,
            cross_predictions=cross_predictions,
            max_features=max_features,
        )
        for source in SOURCES
    ]
    return {
        "status": "ok",
        "scope": "learned_content_router_leave_one_source",
        "protocol": {
            "router": "character n-gram naive bayes over diff-body-only text",
            "max_features": max_features,
            "stress_type": "leave-one-source-out open-set routing boundary",
            "interpretation": (
                "For each source, the router is trained only on the other two sources and must map held-out rows "
                "to one of the available existing experts. This is not expected to recover the hidden source label; "
                "it tests whether source/expert routing has a graceful fallback boundary under unseen-source shift."
            ),
        },
        "heldout_results": results,
        "conclusion": (
            "Leave-one-source-out routing should be read as an open-set boundary test. If routed existing experts trail "
            "the source-specific oracle, the system should keep source-aware routing as a closed-world adapter selection "
            "claim rather than a deployment-grade unseen-source expert discovery claim."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content Router Leave-One-Source Stress",
        "",
        "This report holds out one source at router-training time and forces held-out rows to route to one of the remaining source experts.",
        "",
        "## Protocol",
        "",
        f"- Router: `{payload['protocol']['router']}`",
        f"- Max features: `{payload['protocol']['max_features']}`",
        f"- Stress type: `{payload['protocol']['stress_type']}`",
        "",
        "## Held-Out Source Results",
        "",
        "| Held-out source | Train sources | Held-out rows | Route distribution | Routed BA | Single BA | Oracle BA | Routed - single BA | Routed - oracle BA | Fallback rows |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in payload["heldout_results"]:
        systems = {system["system"]: system for system in result["systems"]}
        single = systems["heldout single matched-mixed checkpoint"]
        oracle = systems["heldout source-specific expert"]
        routed = systems["heldout leave-one-source routed existing experts"]
        lines.append(
            f"| `{result['heldout_source']}` | `{', '.join(result['train_sources'])}` | `{result['heldout_eval_rows']}` | "
            f"`{result['heldout_route_distribution']}` | `{routed['overall']['balanced_accuracy']}` | "
            f"`{single['overall']['balanced_accuracy']}` | `{oracle['overall']['balanced_accuracy']}` | "
            f"`{result['deltas']['routed_minus_single']['balanced_accuracy']}` | "
            f"`{result['deltas']['routed_minus_oracle']['balanced_accuracy']}` | "
            f"`{sum(result['fallback_counts'].values())}` |"
        )
    lines.extend(
        [
            "",
            "## Seen-Source Router Sanity",
            "",
            "| Held-out source | Seen-source row accuracy | Seen-source pair accuracy |",
            "| --- | ---: | ---: |",
        ]
    )
    for result in payload["heldout_results"]:
        metrics = result["seen_source_routing_metrics"]
        lines.append(f"| `{result['heldout_source']}` | `{metrics['row_accuracy']}` | `{metrics['pair_group_accuracy']}` |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned content-router leave-one-source stress report.")
    parser.add_argument("--train-prime", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--train-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--train-patch", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-prime", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--eval-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--eval-patch", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_router_leave_one_source_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_ROUTER_LEAVE_ONE_SOURCE.md")
    args = parser.parse_args()

    train_metadata_by_source = {
        "PrimeVul-time": read_jsonl(args.train_prime),
        "DeltaSecommits": read_jsonl(args.train_delta),
        "PatchEval": read_jsonl(args.train_patch),
    }
    eval_metadata_by_source = {
        "PrimeVul-time": read_jsonl(args.eval_prime),
        "DeltaSecommits": read_jsonl(args.eval_delta),
        "PatchEval": read_jsonl(args.eval_patch),
    }
    artifacts = build_default_artifacts(train_metadata_by_source, eval_metadata_by_source)
    payload = build_report(
        train_metadata_by_source=artifacts["train_metadata_by_source"],
        eval_metadata_by_source=artifacts["eval_metadata_by_source"],
        matched_predictions=artifacts["matched_predictions"],
        expert_predictions=artifacts["expert_predictions"],
        cross_predictions=artifacts["cross_predictions"],
        max_features=args.max_features,
    )
    write_json(args.json_output, payload)
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
