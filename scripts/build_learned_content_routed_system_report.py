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

from scripts.build_learned_content_source_router_report import SOURCES, examples, predict_one, train_nb
from scripts.build_non_oracle_source_router_report import read_jsonl
from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = ROOT / path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def normalize_metadata(source: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        pair_key = str(row.get("pair_key") or row.get("id"))
        normalized.append(
            {
                "id": str(row["id"]),
                "row_key": f"{source}::{index}::{row['id']}",
                "source": source,
                "pair_key": f"{source}::{pair_key}",
                "gold": int(bool(row.get("has_vulnerability"))),
                "metadata": row,
            }
        )
    return normalized


def read_predictions(path: str | Path) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in read_jsonl(path)}


def read_prediction_list(path: str | Path) -> list[dict[str, Any]]:
    return read_jsonl(path)


def coupled_prediction_rows(
    *,
    source: str,
    metadata_rows: list[dict[str, Any]],
    prediction_path: str | Path,
    threshold: float,
    margin: float,
    adapter: str,
    align_by_id: bool = False,
) -> dict[str, dict[str, Any]]:
    metadata = normalize_metadata(source, metadata_rows)
    if align_by_id:
        by_id = read_predictions(prediction_path)
        predictions = [by_id[item["id"]] for item in metadata]
    else:
        predictions = read_prediction_list(prediction_path)
        if len(predictions) != len(metadata):
            raise ValueError(f"{prediction_path} has {len(predictions)} rows but {source} metadata has {len(metadata)} rows")
    rows: list[dict[str, Any]] = []
    for item, pred in zip(metadata, predictions, strict=True):
        probability = float(pred["vuln_probability"])
        rows.append(
            {
                "id": item["row_key"],
                "source_id": item["id"],
                "source": source,
                "adapter": adapter,
                "gold": item["gold"],
                "pred": int(probability >= threshold),
                "vuln_probability": probability,
                "pair_key": item["pair_key"],
            }
        )
    coupled, _counts = apply_pair_coupling(rows, margin=margin)
    return {str(row["id"]): row for row in coupled}


def final_prediction_rows(
    *,
    source: str,
    metadata_rows: list[dict[str, Any]],
    prediction_path: str | Path,
    adapter: str,
) -> dict[str, dict[str, Any]]:
    predictions = read_prediction_list(prediction_path)
    metadata = normalize_metadata(source, metadata_rows)
    if len(predictions) != len(metadata):
        raise ValueError(f"{prediction_path} has {len(predictions)} rows but {source} metadata has {len(metadata)} rows")
    rows: dict[str, dict[str, Any]] = {}
    for item, pred in zip(metadata, predictions, strict=True):
        rows[item["row_key"]] = {
            "id": item["row_key"],
            "source_id": item["id"],
            "source": source,
            "adapter": adapter,
            "gold": item["gold"],
            "pred": int(pred["pred"]),
            "vuln_probability": float(pred["vuln_probability"]),
            "pair_key": item["pair_key"],
        }
    return rows


def system_metrics(name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "system": name,
        "overall": compute_binary_metrics(rows),
        "group_metrics": compute_group_metrics(rows),
        "route_counts": dict(Counter(str(row.get("route")) for row in rows)),
        "adapter_counts": dict(Counter(str(row.get("adapter")) for row in rows)),
        "source_counts": dict(Counter(str(row.get("source")) for row in rows)),
    }


def route_predictions(
    *,
    metadata_by_source: dict[str, list[dict[str, Any]]],
    routing_by_id: dict[str, str],
    prediction_matrix: dict[tuple[str, str], dict[str, dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    fallback_counts: Counter[str] = Counter()
    for source, source_rows in metadata_by_source.items():
        for item in normalize_metadata(source, source_rows):
            routed_source = routing_by_id[item["row_key"]]
            matrix_key = (source, routed_source)
            route = f"{source}->{routed_source}"
            if matrix_key in prediction_matrix:
                selected = dict(prediction_matrix[matrix_key][item["row_key"]])
                selected["route"] = route
            else:
                selected = dict(matched_predictions[source][item["row_key"]])
                selected["route"] = f"{route} fallback:matched-mixed"
                fallback_counts[route] += 1
            selected["true_source"] = source
            selected["routed_source"] = routed_source
            rows.append(selected)
    return rows, dict(fallback_counts)


def build_report(
    *,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    max_features: int = 50000,
) -> dict[str, Any]:
    train_examples = examples(train_metadata_by_source, mode="diff_body")
    model = train_nb(train_examples, max_features=max_features)
    routing_by_key: dict[str, str] = {}
    route_rows: list[dict[str, Any]] = []
    for source, source_rows in eval_metadata_by_source.items():
        for item in normalize_metadata(source, source_rows):
            row = item["metadata"]
            predicted_source = predict_one(model, examples({source: [row]}, mode="diff_body")[0]["text"])
            routing_by_key[item["row_key"]] = predicted_source
            route_rows.append(
                {
                    "true_source": source,
                    "predicted_source": predicted_source,
                    "id": item["id"],
                    "row_key": item["row_key"],
                    "pair_key": str(row.get("pair_key") or row.get("id")),
                }
            )

    prediction_matrix: dict[tuple[str, str], dict[str, dict[str, Any]]] = {
        (source, source): rows for source, rows in expert_predictions.items()
    }
    prediction_matrix.update(cross_predictions)

    single_rows = [row for source_rows in matched_predictions.values() for row in source_rows.values()]
    oracle_rows = [row for source_rows in expert_predictions.values() for row in source_rows.values()]
    learned_rows, fallback_counts = route_predictions(
        metadata_by_source=eval_metadata_by_source,
        routing_by_id=routing_by_key,
        prediction_matrix=prediction_matrix,
        matched_predictions=matched_predictions,
    )
    route_confusion: dict[str, dict[str, int]] = {}
    for row in route_rows:
        route_confusion.setdefault(row["true_source"], {})
        route_confusion[row["true_source"]][row["predicted_source"]] = (
            route_confusion[row["true_source"]].get(row["predicted_source"], 0) + 1
        )
    correct_routes = sum(1 for row in route_rows if row["true_source"] == row["predicted_source"])
    return {
        "status": "ok",
        "scope": "learned_content_routed_system",
        "protocol": {
            "router": "character n-gram naive bayes over diff-body-only text",
            "max_features": max_features,
            "routing_rows": len(route_rows),
            "routing_accuracy": round(correct_routes / len(route_rows), 4) if route_rows else 0.0,
            "prediction_matrix_policy": (
                "Use source-specific expert predictions when the learned route has a materialized prediction file. "
                "If a cross-source expert prediction is missing for the routed source, fall back to the single matched-mixed checkpoint and count that fallback explicitly."
            ),
            "available_cross_predictions": [f"{source}->{routed}" for source, routed in sorted(cross_predictions)],
            "missing_cross_prediction_fallbacks": fallback_counts,
        },
        "routing_confusion": route_confusion,
        "systems": [
            system_metrics("single matched-mixed checkpoint", single_rows),
            system_metrics("oracle source-routed experts", oracle_rows),
            system_metrics("learned diff-body router with available cross-prediction fallback", learned_rows),
        ],
        "deltas": {},
        "conclusion": (
            "The learned diff-body router can now be evaluated as a routed system rather than only as a source classifier. "
            "The current result should still be read with its fallback policy: several cross-expert prediction files are not yet materialized, so misroutes without cross predictions use the matched-mixed fallback instead of an unobserved expert output."
        ),
    }


def add_deltas(payload: dict[str, Any]) -> None:
    single = payload["systems"][0]
    oracle = payload["systems"][1]
    learned = payload["systems"][2]
    payload["deltas"] = {
        "learned_minus_single": {
            "balanced_accuracy": round(learned["overall"]["balanced_accuracy"] - single["overall"]["balanced_accuracy"], 4),
            "f1": round(learned["overall"]["f1"] - single["overall"]["f1"], 4),
            "group_all_correct_rate": round(
                learned["group_metrics"]["group_all_correct_rate"] - single["group_metrics"]["group_all_correct_rate"], 4
            ),
            "orientation_accuracy": round(
                learned["group_metrics"]["orientation_accuracy"] - single["group_metrics"]["orientation_accuracy"], 4
            ),
        },
        "learned_minus_oracle": {
            "balanced_accuracy": round(learned["overall"]["balanced_accuracy"] - oracle["overall"]["balanced_accuracy"], 4),
            "f1": round(learned["overall"]["f1"] - oracle["overall"]["f1"], 4),
            "group_all_correct_rate": round(
                learned["group_metrics"]["group_all_correct_rate"] - oracle["group_metrics"]["group_all_correct_rate"], 4
            ),
            "orientation_accuracy": round(
                learned["group_metrics"]["orientation_accuracy"] - oracle["group_metrics"]["orientation_accuracy"], 4
            ),
        },
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content-Routed System",
        "",
        "This report turns the learned diff-body source router into an end-to-end routed-system evaluation.",
        "",
        "## Protocol",
        "",
        f"- Router: `{payload['protocol']['router']}`",
        f"- Routing accuracy: `{payload['protocol']['routing_accuracy']}`",
        f"- Available cross predictions: `{', '.join(payload['protocol']['available_cross_predictions'])}`",
        f"- Missing cross-prediction fallbacks: `{payload['protocol']['missing_cross_prediction_fallbacks']}`",
        "",
        "## System Results",
        "",
        "| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for system in payload["systems"]:
        overall = system["overall"]
        group = system["group_metrics"]
        lines.append(
            f"| `{system['system']}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
            f"`{overall['safe_specificity']}` | `{overall['f1']}` | `{group['group_all_correct_rate']}` | "
            f"`{group['orientation_accuracy']}` |"
        )
    delta = payload["deltas"]["learned_minus_single"]
    oracle_delta = payload["deltas"]["learned_minus_oracle"]
    lines.extend(
        [
            "",
            "## Deltas",
            "",
            f"- Learned minus single BA: `{delta['balanced_accuracy']}`",
            f"- Learned minus single group all-correct: `{delta['group_all_correct_rate']}`",
            f"- Learned minus oracle BA: `{oracle_delta['balanced_accuracy']}`",
            f"- Learned minus oracle group all-correct: `{oracle_delta['group_all_correct_rate']}`",
            "",
            "## Routing Confusion",
            "",
            "```json",
            json.dumps(payload["routing_confusion"], indent=2, ensure_ascii=False),
            "```",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned content-routed system report.")
    parser.add_argument("--train-prime", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--train-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--train-patch", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-prime", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--eval-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--eval-patch", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_routed_system_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_ROUTED_SYSTEM.md")
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
    }
    payload = build_report(
        train_metadata_by_source=train_metadata_by_source,
        eval_metadata_by_source=eval_metadata_by_source,
        matched_predictions=matched_predictions,
        expert_predictions=expert_predictions,
        cross_predictions=cross_predictions,
        max_features=args.max_features,
    )
    add_deltas(payload)
    write_json(args.json_output, payload)
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
