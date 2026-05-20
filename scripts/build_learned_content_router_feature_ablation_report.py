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
from scripts.build_learned_content_routed_system_report import normalize_metadata, route_predictions, system_metrics
from scripts.build_learned_content_router_leave_one_source_report import build_default_artifacts
from scripts.build_learned_content_source_router_report import SOURCES, examples, predict_one, train_nb
from scripts.build_non_oracle_source_router_report import read_jsonl


FEATURE_MODES = ["char_3_5", "token_1_2", "diff_line_markers"]


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = ROOT / path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def routing_for_model(
    *,
    model: dict[str, Any],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    routing_by_key: dict[str, str] = {}
    route_rows: list[dict[str, Any]] = []
    for source, source_rows in eval_metadata_by_source.items():
        for item in normalize_metadata(source, source_rows):
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


def build_prediction_matrix(
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    prediction_matrix = {(source, source): rows for source, rows in expert_predictions.items()}
    prediction_matrix.update(cross_predictions)
    return prediction_matrix


def system_delta(candidate: dict[str, Any], baseline: dict[str, Any], section: str, metric: str) -> float:
    return round(float(candidate[section][metric]) - float(baseline[section][metric]), 4)


def evaluate_feature_mode(
    *,
    feature_mode: str,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    max_features: int,
) -> dict[str, Any]:
    model = train_nb(
        examples(train_metadata_by_source, mode="diff_body"),
        max_features=max_features,
        feature_mode=feature_mode,
    )
    routing_by_key, route_rows = routing_for_model(model=model, eval_metadata_by_source=eval_metadata_by_source)
    prediction_matrix = build_prediction_matrix(expert_predictions, cross_predictions)
    routed_rows, fallback_counts = route_predictions(
        metadata_by_source=eval_metadata_by_source,
        routing_by_id=routing_by_key,
        prediction_matrix=prediction_matrix,
        matched_predictions=matched_predictions,
    )
    single_rows = [row for source_rows in matched_predictions.values() for row in source_rows.values()]
    oracle_rows = [row for source_rows in expert_predictions.values() for row in source_rows.values()]
    single = system_metrics("single matched-mixed checkpoint", single_rows)
    oracle = system_metrics("oracle source-routed experts", oracle_rows)
    routed = system_metrics(f"learned router {feature_mode}", routed_rows)
    return {
        "feature_mode": feature_mode,
        "model_stats": {
            "vocab_size": model["vocab_size"],
            "train_doc_counts": model["train_doc_counts"],
        },
        "routing_metrics": routing_metrics(route_rows),
        "routing_confusion": {
            source: dict(sorted(Counter(row["predicted_source"] for row in route_rows if row["true_source"] == source).items()))
            for source in SOURCES
        },
        "fallback_counts": fallback_counts,
        "systems": [
            single,
            oracle,
            routed,
        ],
        "deltas": {
            "routed_minus_single": {
                "balanced_accuracy": system_delta(routed, single, "overall", "balanced_accuracy"),
                "group_all_correct_rate": system_delta(routed, single, "group_metrics", "group_all_correct_rate"),
                "orientation_accuracy": system_delta(routed, single, "group_metrics", "orientation_accuracy"),
            },
            "routed_minus_oracle": {
                "balanced_accuracy": system_delta(routed, oracle, "overall", "balanced_accuracy"),
                "group_all_correct_rate": system_delta(routed, oracle, "group_metrics", "group_all_correct_rate"),
                "orientation_accuracy": system_delta(routed, oracle, "group_metrics", "orientation_accuracy"),
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
    feature_modes: list[str] | None = None,
    max_features: int = 50000,
) -> dict[str, Any]:
    modes = feature_modes or FEATURE_MODES
    rows = [
        evaluate_feature_mode(
            feature_mode=mode,
            train_metadata_by_source=train_metadata_by_source,
            eval_metadata_by_source=eval_metadata_by_source,
            matched_predictions=matched_predictions,
            expert_predictions=expert_predictions,
            cross_predictions=cross_predictions,
            max_features=max_features,
        )
        for mode in modes
    ]
    return {
        "status": "ok",
        "scope": "learned_content_router_feature_ablation",
        "protocol": {
            "router": "multinomial naive bayes over diff-body-only text",
            "feature_modes": modes,
            "max_features": max_features,
            "purpose": (
                "Stress whether learned source/expert routing only works with character n-gram fingerprints or "
                "also survives coarser token and diff-line feature views."
            ),
        },
        "feature_results": rows,
        "conclusion": (
            "Feature ablation is a robustness check, not a new headline metric. If token or diff-line features remain competitive, "
            "the router claim is less dependent on a single character-fingerprint representation; if they collapse, the claim should stay narrow."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content Router Feature Ablation",
        "",
        "This report compares diff-body-only source/expert routing across lightweight feature views.",
        "",
        "## Feature Results",
        "",
        "| Feature mode | Route row acc | Route pair acc | Routed BA | Routed group all-correct | Delta vs single BA | Delta vs oracle BA | Fallback rows |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["feature_results"]:
        routed = row["systems"][2]
        metrics = row["routing_metrics"]
        lines.append(
            f"| `{row['feature_mode']}` | `{metrics['row_accuracy']}` | `{metrics['pair_group_accuracy']}` | "
            f"`{routed['overall']['balanced_accuracy']}` | `{routed['group_metrics']['group_all_correct_rate']}` | "
            f"`{row['deltas']['routed_minus_single']['balanced_accuracy']}` | "
            f"`{row['deltas']['routed_minus_oracle']['balanced_accuracy']}` | "
            f"`{sum(row['fallback_counts'].values())}` |"
        )
    lines.extend(
        [
            "",
            "## Per-Source Routing Accuracy",
            "",
            "| Feature mode | PrimeVul-time | DeltaSecommits | PatchEval |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for row in payload["feature_results"]:
        by_source = row["routing_metrics"]["by_source"]
        lines.append(
            f"| `{row['feature_mode']}` | `{by_source['PrimeVul-time']['accuracy']}` | "
            f"`{by_source['DeltaSecommits']['accuracy']}` | `{by_source['PatchEval']['accuracy']}` |"
        )
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
    parser = argparse.ArgumentParser(description="Build learned content-router feature-ablation report.")
    parser.add_argument("--train-prime", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--train-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--train-patch", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-prime", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--eval-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--eval-patch", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--feature-modes", default=",".join(FEATURE_MODES))
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_router_feature_ablation_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_ROUTER_FEATURE_ABLATION.md")
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
        feature_modes=[mode.strip() for mode in args.feature_modes.split(",") if mode.strip()],
        max_features=args.max_features,
    )
    write_json(args.json_output, payload)
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
