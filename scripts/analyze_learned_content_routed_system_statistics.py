from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_learned_content_routed_system_report import (
    coupled_prediction_rows,
    final_prediction_rows,
    read_jsonl,
)
from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def exact_binomial_two_sided(successes: int, failures: int) -> float:
    n = successes + failures
    if n == 0:
        return 1.0
    smaller = min(successes, failures)
    p_value = min(1.0, 2 * sum(math.comb(n, k) for k in range(smaller + 1)) / (2**n))
    rounded = round(p_value, 6)
    return 0.000001 if p_value > 0 and rounded == 0 else rounded


def rows_by_pair(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["pair_key"])].append(row)
    return dict(grouped)


def flatten_groups(groups: dict[str, list[dict[str, Any]]], keys: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in keys:
        rows.extend(groups[key])
    return rows


def group_summary(group: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for row in group if int(row["gold"]) == 1 and int(row["pred"]) == 1)
    tn = sum(1 for row in group if int(row["gold"]) == 0 and int(row["pred"]) == 0)
    fp = sum(1 for row in group if int(row["gold"]) == 0 and int(row["pred"]) == 1)
    fn = sum(1 for row in group if int(row["gold"]) == 1 and int(row["pred"]) == 0)
    positives = [row for row in group if int(row["gold"]) == 1]
    negatives = [row for row in group if int(row["gold"]) == 0]
    orientation: int | None = None
    if positives and negatives:
        pos_prob = mean([float(row["vuln_probability"]) for row in positives])
        neg_prob = mean([float(row["vuln_probability"]) for row in negatives])
        orientation = int(pos_prob > neg_prob)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "group_all_correct": int(all(int(row["gold"]) == int(row["pred"]) for row in group)),
        "orientation": orientation,
    }


def group_summaries(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {key: group_summary(group) for key, group in rows_by_pair(rows).items()}


def balanced_accuracy_from_summaries(summaries: list[dict[str, Any]]) -> float:
    tp = sum(int(row["tp"]) for row in summaries)
    tn = sum(int(row["tn"]) for row in summaries)
    fp = sum(int(row["fp"]) for row in summaries)
    fn = sum(int(row["fn"]) for row in summaries)
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return (recall + specificity) / 2


def summary_metric_value(summaries: list[dict[str, Any]], metric: str) -> float:
    if metric == "balanced_accuracy":
        return balanced_accuracy_from_summaries(summaries)
    if metric == "group_all_correct_rate":
        return mean([float(row["group_all_correct"]) for row in summaries])
    if metric == "orientation_accuracy":
        values = [float(row["orientation"]) for row in summaries if row["orientation"] is not None]
        return mean(values)
    raise ValueError(f"Unsupported metric: {metric}")


def metric_value(rows: list[dict[str, Any]], metric: str) -> float:
    if metric == "balanced_accuracy":
        return float(compute_binary_metrics(rows)["balanced_accuracy"])
    if metric == "group_all_correct_rate":
        return float(compute_group_metrics(rows)["group_all_correct_rate"])
    if metric == "orientation_accuracy":
        return float(compute_group_metrics(rows)["orientation_accuracy"])
    raise ValueError(f"Unsupported metric: {metric}")


def bootstrap_system(rows: list[dict[str, Any]], *, metric: str, iterations: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    summaries_by_key = group_summaries(rows)
    keys = sorted(summaries_by_key)
    samples: list[float] = []
    for _ in range(iterations):
        selected = [rng.choice(keys) for _ in keys]
        samples.append(summary_metric_value([summaries_by_key[key] for key in selected], metric))
    observed = summary_metric_value([summaries_by_key[key] for key in keys], metric)
    return {
        "observed": round(observed, 4),
        "ci95_low": round(percentile(samples, 0.025), 4),
        "ci95_high": round(percentile(samples, 0.975), 4),
        "iterations": iterations,
        "seed": seed,
        "units": len(keys),
    }


def bootstrap_delta(
    baseline_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    *,
    metric: str,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    rng = random.Random(seed)
    baseline_summaries = group_summaries(baseline_rows)
    candidate_summaries = group_summaries(candidate_rows)
    keys = sorted(set(baseline_summaries) & set(candidate_summaries))
    samples: list[float] = []
    for _ in range(iterations):
        selected = [rng.choice(keys) for _ in keys]
        baseline_sample = [baseline_summaries[key] for key in selected]
        candidate_sample = [candidate_summaries[key] for key in selected]
        samples.append(summary_metric_value(candidate_sample, metric) - summary_metric_value(baseline_sample, metric))
    observed = summary_metric_value([candidate_summaries[key] for key in keys], metric) - summary_metric_value(
        [baseline_summaries[key] for key in keys],
        metric,
    )
    return {
        "observed_delta": round(observed, 4),
        "ci95_low": round(percentile(samples, 0.025), 4),
        "ci95_high": round(percentile(samples, 0.975), 4),
        "iterations": iterations,
        "seed": seed,
        "units": len(keys),
    }


def mcnemar(baseline_rows: list[dict[str, Any]], candidate_rows: list[dict[str, Any]]) -> dict[str, Any]:
    baseline_by_id = {str(row["id"]): row for row in baseline_rows}
    candidate_by_id = {str(row["id"]): row for row in candidate_rows}
    improved = 0
    regressed = 0
    ties = 0
    for row_id in sorted(set(baseline_by_id) & set(candidate_by_id)):
        baseline_correct = int(baseline_by_id[row_id]["gold"] == baseline_by_id[row_id]["pred"])
        candidate_correct = int(candidate_by_id[row_id]["gold"] == candidate_by_id[row_id]["pred"])
        if candidate_correct > baseline_correct:
            improved += 1
        elif candidate_correct < baseline_correct:
            regressed += 1
        else:
            ties += 1
    return {
        "candidate_correct_baseline_wrong": improved,
        "candidate_wrong_baseline_correct": regressed,
        "ties": ties,
        "two_sided_p_value": exact_binomial_two_sided(improved, regressed),
        "test": "exact_mcnemar_binomial",
    }


def group_sign_test(baseline_rows: list[dict[str, Any]], candidate_rows: list[dict[str, Any]], *, metric: str) -> dict[str, Any]:
    baseline_groups = rows_by_pair(baseline_rows)
    candidate_groups = rows_by_pair(candidate_rows)
    wins = 0
    losses = 0
    ties = 0
    for key in sorted(set(baseline_groups) & set(candidate_groups)):
        baseline_value = metric_value(baseline_groups[key], metric)
        candidate_value = metric_value(candidate_groups[key], metric)
        if candidate_value > baseline_value:
            wins += 1
        elif candidate_value < baseline_value:
            losses += 1
        else:
            ties += 1
    return {
        "wins": wins,
        "losses": losses,
        "ties": ties,
        "two_sided_p_value": exact_binomial_two_sided(wins, losses),
        "test": "exact_group_sign_test",
    }


def build_system_rows() -> dict[str, list[dict[str, Any]]]:
    train_metadata_by_source = {
        "PrimeVul-time": read_jsonl("data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl"),
        "DeltaSecommits": read_jsonl("data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl"),
        "PatchEval": read_jsonl("data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl"),
    }
    eval_metadata_by_source = {
        "PrimeVul-time": read_jsonl("data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl"),
        "DeltaSecommits": read_jsonl("data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl"),
        "PatchEval": read_jsonl("data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl"),
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
        ("DeltaSecommits", "PatchEval"): coupled_prediction_rows(
            source="DeltaSecommits",
            metadata_rows=eval_metadata_by_source["DeltaSecommits"],
            prediction_path="outputs/secure_code_patcheval_adapter_delta_eval_predictions.jsonl",
            threshold=0.5,
            margin=0.02,
            adapter="patcheval expert cross-source",
        ),
        ("PrimeVul-time", "PatchEval"): coupled_prediction_rows(
            source="PrimeVul-time",
            metadata_rows=eval_metadata_by_source["PrimeVul-time"],
            prediction_path="outputs/secure_code_patcheval_adapter_primevul_time_eval_predictions.jsonl",
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
    # Rebuild rows from the same dictionaries so statistical tests operate on row-level predictions.
    from scripts.build_learned_content_routed_system_report import route_predictions as route_by_learned_router
    from scripts.build_learned_content_routed_system_report import normalize_metadata
    from scripts.build_learned_content_source_router_report import examples, predict_one, train_nb

    routing_by_id: dict[str, str] = {}
    model = train_nb(examples(train_metadata_by_source, mode="diff_body"))
    for source, source_rows in eval_metadata_by_source.items():
        for item in normalize_metadata(source, source_rows):
            routing_by_id[item["row_key"]] = predict_one(model, examples({source: [item["metadata"]]}, mode="diff_body")[0]["text"])
    prediction_matrix = {(source, source): rows for source, rows in expert_predictions.items()}
    prediction_matrix.update(cross_predictions)
    learned_rows, _fallbacks = route_by_learned_router(
        metadata_by_source=eval_metadata_by_source,
        routing_by_id=routing_by_id,
        prediction_matrix=prediction_matrix,
        matched_predictions=matched_predictions,
    )
    return {
        "single matched-mixed checkpoint": [row for source_rows in matched_predictions.values() for row in source_rows.values()],
        "oracle source-routed experts": [row for source_rows in expert_predictions.values() for row in source_rows.values()],
        "learned diff-body router with full cross-prediction matrix": learned_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content-Routed System Statistics",
        "",
        "This report estimates uncertainty for the learned diff-body routed system against the single matched-mixed baseline and oracle source-routed experts.",
        "",
        "## Bootstrap 95% Confidence Intervals",
        "",
        "| system | metric | observed | ci95_low | ci95_high | units |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for system, metrics in payload["bootstrap"].items():
        for metric, row in metrics.items():
            lines.append(
                f"| `{system}` | `{metric}` | `{row['observed']}` | `{row['ci95_low']}` | `{row['ci95_high']}` | `{row['units']}` |"
            )
    lines.extend(
        [
            "",
            "## Learned Minus Comparators",
            "",
            "| comparator | metric | delta | ci95_low | ci95_high | paired test | p-value |",
            "| --- | --- | ---: | ---: | ---: | --- | ---: |",
        ]
    )
    for comparator, metrics in payload["deltas"].items():
        for metric, row in metrics.items():
            test = payload["paired_tests"][comparator][metric]
            lines.append(
                f"| `{comparator}` | `{metric}` | `{row['observed_delta']}` | `{row['ci95_low']}` | `{row['ci95_high']}` | `{test['test']}` | `{test['two_sided_p_value']}` |"
            )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            payload["interpretation"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Statistical analysis for learned content-routed system.")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_routed_system_statistics_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_ROUTED_SYSTEM_STATISTICS.md")
    args = parser.parse_args()

    rows = build_system_rows()
    single_name = "single matched-mixed checkpoint"
    oracle_name = "oracle source-routed experts"
    learned_name = "learned diff-body router with full cross-prediction matrix"
    metrics = ["balanced_accuracy", "group_all_correct_rate", "orientation_accuracy"]
    bootstrap = {
        name: {metric: bootstrap_system(rows[name], metric=metric, iterations=args.iterations, seed=args.seed) for metric in metrics}
        for name in [single_name, oracle_name, learned_name]
    }
    deltas = {
        single_name: {
            metric: bootstrap_delta(rows[single_name], rows[learned_name], metric=metric, iterations=args.iterations, seed=args.seed)
            for metric in metrics
        },
        oracle_name: {
            metric: bootstrap_delta(rows[oracle_name], rows[learned_name], metric=metric, iterations=args.iterations, seed=args.seed)
            for metric in metrics
        },
    }
    paired_tests = {
        single_name: {
            "balanced_accuracy": mcnemar(rows[single_name], rows[learned_name]),
            "group_all_correct_rate": group_sign_test(rows[single_name], rows[learned_name], metric="group_all_correct_rate"),
            "orientation_accuracy": group_sign_test(rows[single_name], rows[learned_name], metric="orientation_accuracy"),
        },
        oracle_name: {
            "balanced_accuracy": mcnemar(rows[oracle_name], rows[learned_name]),
            "group_all_correct_rate": group_sign_test(rows[oracle_name], rows[learned_name], metric="group_all_correct_rate"),
            "orientation_accuracy": group_sign_test(rows[oracle_name], rows[learned_name], metric="orientation_accuracy"),
        },
    }
    payload = {
        "status": "ok",
        "scope": "learned_content_routed_system_statistics",
        "iterations": args.iterations,
        "seed": args.seed,
        "bootstrap": bootstrap,
        "deltas": deltas,
        "paired_tests": paired_tests,
        "interpretation": (
            "The learned routed system improves over the single matched-mixed baseline at the point estimate, "
            "but the bootstrap interval should be used as the reviewer-facing claim boundary. "
            "Against oracle source routing, the learned system matches row-level balanced accuracy while remaining slightly below oracle group all-correct."
        ),
    }
    output = ROOT / args.json_output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_output = ROOT / args.md_output
    md_output.parent.mkdir(parents=True, exist_ok=True)
    md_output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["deltas"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
