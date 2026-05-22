from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_content_source_router_report import routing_metrics
from scripts.build_learned_content_routed_system_report import normalize_metadata, route_predictions, system_metrics
from scripts.build_learned_content_router_feature_ablation_report import build_prediction_matrix
from scripts.build_learned_content_router_leave_one_source_report import build_default_artifacts
from scripts.build_learned_content_source_router_report import SOURCES, examples, feature_counts, input_text, predict_one
from scripts.build_non_oracle_source_router_report import read_jsonl


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = ROOT / path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def pair_key(row: dict[str, Any]) -> str:
    return str(row.get("pair_key") or row.get("id"))


def sample_rows_by_pair(
    rows: list[dict[str, Any]],
    *,
    fraction: float,
    seed: int,
) -> list[dict[str, Any]]:
    if not 0 < fraction <= 1:
        raise ValueError(f"fraction must be in (0, 1], got {fraction}")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[pair_key(row)].append(row)
    keys = sorted(groups)
    if fraction >= 1:
        selected = keys
    else:
        rng = random.Random(seed)
        selected_count = max(1, round(len(keys) * fraction))
        selected = sorted(rng.sample(keys, selected_count))
    sampled: list[dict[str, Any]] = []
    for key in selected:
        sampled.extend(groups[key])
    return sampled


def cached_examples_by_source(
    metadata_by_source: dict[str, list[dict[str, Any]]],
    *,
    feature_mode: str,
) -> dict[str, list[dict[str, Any]]]:
    cached: dict[str, list[dict[str, Any]]] = {}
    for source, rows in metadata_by_source.items():
        cached[source] = []
        for index, row in enumerate(rows):
            cached[source].append(
                {
                    "true_source": source,
                    "id": str(row["id"]),
                    "row_key": f"{source}::{index}::{row['id']}",
                    "pair_key": pair_key(row),
                    "features": feature_counts(input_text(row, "diff_body"), feature_mode=feature_mode),
                }
            )
    return cached


def sample_cached_by_pair(
    rows: list[dict[str, Any]],
    *,
    fraction: float,
    seed: int,
) -> list[dict[str, Any]]:
    if not 0 < fraction <= 1:
        raise ValueError(f"fraction must be in (0, 1], got {fraction}")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["pair_key"])].append(row)
    keys = sorted(groups)
    if fraction >= 1:
        selected = keys
    else:
        rng = random.Random(seed)
        selected_count = max(1, round(len(keys) * fraction))
        selected = sorted(rng.sample(keys, selected_count))
    sampled: list[dict[str, Any]] = []
    for key in selected:
        sampled.extend(groups[key])
    return sampled


def select_cached_vocabulary(
    train_examples: list[dict[str, Any]],
    *,
    max_features: int,
) -> set[str]:
    doc_freq: Counter[str] = Counter()
    for row in train_examples:
        doc_freq.update(row["features"].keys())
    return {feature for feature, _count in doc_freq.most_common(max_features)}


def train_cached_nb(
    train_examples: list[dict[str, Any]],
    *,
    max_features: int,
    classes: list[str] | None = None,
    alpha: float = 1.0,
    feature_mode: str,
) -> dict[str, Any]:
    class_names = classes or SOURCES
    vocab = select_cached_vocabulary(train_examples, max_features=max_features)
    class_doc_counts: Counter[str] = Counter()
    token_counts: dict[str, Counter[str]] = {source: Counter() for source in class_names}
    token_totals: Counter[str] = Counter()
    for row in train_examples:
        source = row["true_source"]
        if source not in token_counts:
            raise ValueError(f"Training example source {source!r} is not in classes: {class_names}")
        class_doc_counts[source] += 1
        for feature, count in row["features"].items():
            if feature not in vocab:
                continue
            token_counts[source][feature] += count
            token_totals[source] += count
    total_docs = sum(class_doc_counts.values())
    vocab_size = len(vocab)
    return {
        "classes": class_names,
        "vocab": vocab,
        "alpha": alpha,
        "feature_mode": feature_mode,
        "class_log_prior": {
            source: math.log((class_doc_counts[source] + alpha) / (total_docs + alpha * len(class_names)))
            for source in class_names
        },
        "token_log_prob": {
            source: {
                feature: math.log((count + alpha) / (token_totals[source] + alpha * vocab_size))
                for feature, count in token_counts[source].items()
            }
            for source in class_names
        },
        "unknown_log_prob": {
            source: math.log(alpha / (token_totals[source] + alpha * vocab_size)) for source in class_names
        },
        "train_doc_counts": dict(class_doc_counts),
        "vocab_size": vocab_size,
    }


def predict_cached(model: dict[str, Any], features: Counter[str]) -> str:
    vocab = model["vocab"]
    scores: dict[str, float] = {}
    for source in model["classes"]:
        score = float(model["class_log_prior"][source])
        token_log_prob = model["token_log_prob"][source]
        unknown = float(model["unknown_log_prob"][source])
        for feature, count in features.items():
            if feature not in vocab:
                continue
            score += count * float(token_log_prob.get(feature, unknown))
        scores[source] = score
    return max(scores.items(), key=lambda item: (item[1], item[0]))[0]


def route_cached_eval(
    *,
    model: dict[str, Any],
    eval_features_by_source: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    routing_by_key: dict[str, str] = {}
    route_rows: list[dict[str, Any]] = []
    for source, rows in eval_features_by_source.items():
        for row in rows:
            predicted_source = predict_cached(model, row["features"])
            routing_by_key[row["row_key"]] = predicted_source
            route_rows.append(
                {
                    "true_source": source,
                    "predicted_source": predicted_source,
                    "id": row["id"],
                    "row_key": row["row_key"],
                    "pair_key": row["pair_key"],
                }
            )
    return routing_by_key, route_rows


def route_eval(
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
                    "pair_key": pair_key(item["metadata"]),
                }
            )
    return routing_by_key, route_rows


def flatten_rows(rows_by_source: dict[str, dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [row for source_rows in rows_by_source.values() for row in source_rows.values()]


def metric_delta(candidate: dict[str, Any], baseline: dict[str, Any], section: str, metric: str) -> float:
    return round(float(candidate[section][metric]) - float(baseline[section][metric]), 4)


def round_mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def value_range(values: list[float]) -> list[float]:
    return [round(min(values), 4), round(max(values), 4)] if values else [0.0, 0.0]


def summarize_metric(rows: list[dict[str, Any]], path: list[str]) -> dict[str, Any]:
    values: list[float] = []
    for row in rows:
        item: Any = row
        for key in path:
            item = item[key]
        values.append(float(item))
    return {
        "mean": round_mean(values),
        "min": value_range(values)[0],
        "max": value_range(values)[1],
    }


def source_rows(rows: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("source") == source or row.get("true_source") == source]


def evaluate_seed_fraction(
    *,
    seed: int,
    train_fraction: float,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    train_features_by_source: dict[str, list[dict[str, Any]]] | None = None,
    eval_features_by_source: dict[str, list[dict[str, Any]]] | None = None,
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    max_features: int,
    feature_mode: str,
) -> dict[str, Any]:
    if train_features_by_source is not None and eval_features_by_source is not None:
        sampled_train_features = {
            source: sample_cached_by_pair(rows, fraction=train_fraction, seed=seed)
            for source, rows in train_features_by_source.items()
        }
        train_examples = [row for rows in sampled_train_features.values() for row in rows]
        model = train_cached_nb(
            train_examples,
            max_features=max_features,
            feature_mode=feature_mode,
        )
        routing_by_key, route_rows = route_cached_eval(model=model, eval_features_by_source=eval_features_by_source)
        train_pair_groups = {
            source: len({str(row["pair_key"]) for row in rows})
            for source, rows in sampled_train_features.items()
        }
    else:
        sampled_train = {
            source: sample_rows_by_pair(rows, fraction=train_fraction, seed=seed)
            for source, rows in train_metadata_by_source.items()
        }
        # This fallback keeps the function easy to unit-test, but normal report generation uses cached features.
        train_features = cached_examples_by_source(sampled_train, feature_mode=feature_mode)
        eval_features = cached_examples_by_source(eval_metadata_by_source, feature_mode=feature_mode)
        train_examples = [row for rows in train_features.values() for row in rows]
        model = train_cached_nb(
            train_examples,
            max_features=max_features,
            feature_mode=feature_mode,
        )
        routing_by_key, route_rows = route_cached_eval(model=model, eval_features_by_source=eval_features)
        train_pair_groups = {
            source: len({pair_key(row) for row in rows})
            for source, rows in sampled_train.items()
        }
    prediction_matrix = build_prediction_matrix(expert_predictions, cross_predictions)
    learned_rows, fallback_counts = route_predictions(
        metadata_by_source=eval_metadata_by_source,
        routing_by_id=routing_by_key,
        prediction_matrix=prediction_matrix,
        matched_predictions=matched_predictions,
    )
    single_rows = flatten_rows(matched_predictions)
    oracle_rows = flatten_rows(expert_predictions)
    single = system_metrics("single matched-mixed checkpoint", single_rows)
    oracle = system_metrics("oracle source-routed experts", oracle_rows)
    learned = system_metrics("learned diff-body routed system", learned_rows)
    per_source: dict[str, Any] = {}
    for source in SOURCES:
        source_single = system_metrics(f"{source} single matched-mixed", source_rows(single_rows, source))
        source_oracle = system_metrics(f"{source} source expert", source_rows(oracle_rows, source))
        source_learned = system_metrics(f"{source} learned routed", source_rows(learned_rows, source))
        per_source[source] = {
            "single_ba": source_single["overall"]["balanced_accuracy"],
            "oracle_ba": source_oracle["overall"]["balanced_accuracy"],
            "learned_ba": source_learned["overall"]["balanced_accuracy"],
            "learned_minus_single_ba": metric_delta(source_learned, source_single, "overall", "balanced_accuracy"),
            "learned_minus_oracle_ba": metric_delta(source_learned, source_oracle, "overall", "balanced_accuracy"),
            "route_accuracy": routing_metrics([row for row in route_rows if row["true_source"] == source])["row_accuracy"],
        }
    return {
        "seed": seed,
        "train_fraction": train_fraction,
        "feature_mode": feature_mode,
        "train_pair_groups": train_pair_groups,
        "routing_metrics": routing_metrics(route_rows),
        "routing_confusion": {
            source: dict(sorted(Counter(row["predicted_source"] for row in route_rows if row["true_source"] == source).items()))
            for source in SOURCES
        },
        "systems": {
            "single": single,
            "oracle": oracle,
            "learned": learned,
        },
        "deltas": {
            "learned_minus_single_ba": metric_delta(learned, single, "overall", "balanced_accuracy"),
            "learned_minus_oracle_ba": metric_delta(learned, oracle, "overall", "balanced_accuracy"),
            "learned_minus_single_group_all_correct": metric_delta(
                learned, single, "group_metrics", "group_all_correct_rate"
            ),
            "learned_minus_oracle_group_all_correct": metric_delta(
                learned, oracle, "group_metrics", "group_all_correct_rate"
            ),
        },
        "per_source_tradeoff": per_source,
        "fallback_counts": fallback_counts,
    }


def summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    by_fraction: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        by_fraction[str(run["train_fraction"])].append(run)
    summaries: dict[str, Any] = {}
    for fraction, fraction_runs in sorted(by_fraction.items(), key=lambda item: float(item[0])):
        source_summary: dict[str, Any] = {}
        for source in SOURCES:
            source_rows_for_fraction = [run["per_source_tradeoff"][source] for run in fraction_runs]
            source_summary[source] = {
                "route_accuracy": summarize_metric(source_rows_for_fraction, ["route_accuracy"]),
                "learned_ba": summarize_metric(source_rows_for_fraction, ["learned_ba"]),
                "learned_minus_single_ba": summarize_metric(source_rows_for_fraction, ["learned_minus_single_ba"]),
                "learned_minus_oracle_ba": summarize_metric(source_rows_for_fraction, ["learned_minus_oracle_ba"]),
            }
        summaries[fraction] = {
            "runs": len(fraction_runs),
            "routing_row_accuracy": summarize_metric(fraction_runs, ["routing_metrics", "row_accuracy"]),
            "routing_pair_accuracy": summarize_metric(fraction_runs, ["routing_metrics", "pair_group_accuracy"]),
            "learned_ba": summarize_metric(fraction_runs, ["systems", "learned", "overall", "balanced_accuracy"]),
            "learned_group_all_correct": summarize_metric(
                fraction_runs, ["systems", "learned", "group_metrics", "group_all_correct_rate"]
            ),
            "learned_minus_single_ba": summarize_metric(fraction_runs, ["deltas", "learned_minus_single_ba"]),
            "learned_minus_oracle_ba": summarize_metric(fraction_runs, ["deltas", "learned_minus_oracle_ba"]),
            "per_source": source_summary,
        }
    return summaries


def build_report(
    *,
    train_metadata_by_source: dict[str, list[dict[str, Any]]],
    eval_metadata_by_source: dict[str, list[dict[str, Any]]],
    matched_predictions: dict[str, dict[str, dict[str, Any]]],
    expert_predictions: dict[str, dict[str, dict[str, Any]]],
    cross_predictions: dict[tuple[str, str], dict[str, dict[str, Any]]],
    seeds: list[int] | None = None,
    train_fractions: list[float] | None = None,
    max_features: int = 50000,
    feature_mode: str = "char_3_5",
) -> dict[str, Any]:
    selected_seeds = seeds or [7, 42, 123]
    selected_fractions = train_fractions or [0.5, 1.0]
    train_features_by_source = cached_examples_by_source(train_metadata_by_source, feature_mode=feature_mode)
    eval_features_by_source = cached_examples_by_source(eval_metadata_by_source, feature_mode=feature_mode)
    runs = [
        evaluate_seed_fraction(
            seed=seed,
            train_fraction=fraction,
            train_metadata_by_source=train_metadata_by_source,
            eval_metadata_by_source=eval_metadata_by_source,
            train_features_by_source=train_features_by_source,
            eval_features_by_source=eval_features_by_source,
            matched_predictions=matched_predictions,
            expert_predictions=expert_predictions,
            cross_predictions=cross_predictions,
            max_features=max_features,
            feature_mode=feature_mode,
        )
        for fraction in selected_fractions
        for seed in selected_seeds
    ]
    return {
        "status": "ok",
        "scope": "learned_content_router_stability",
        "protocol": {
            "router": "multinomial naive bayes over diff-body-only text",
            "feature_mode": feature_mode,
            "seeds": selected_seeds,
            "train_fractions": selected_fractions,
            "sampling_unit": "pair_key within each source",
            "purpose": (
                "Stress whether learned source/expert routing remains useful under smaller source-router training subsets, "
                "and expose the per-source tradeoff between single matched-mixed, source-specific oracle, and learned routing."
            ),
        },
        "summary_by_train_fraction": summarize_runs(runs),
        "runs": runs,
        "conclusion": (
            "This stability report is a router-level stress test, not a new detector training result. "
            "If routed BA stays close to the full-data run under subsampling, the source-router claim is more stable; "
            "if per-source deltas vary, the honest claim should emphasize source-specialization tradeoffs rather than universal routing gains."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content Router Stability",
        "",
        "This report stress-tests diff-body-only source/expert routing under multi-seed pair-group subsampling.",
        "",
        "## Protocol",
        "",
        f"- Router: `{payload['protocol']['router']}`",
        f"- Feature mode: `{payload['protocol']['feature_mode']}`",
        f"- Seeds: `{payload['protocol']['seeds']}`",
        f"- Train fractions: `{payload['protocol']['train_fractions']}`",
        f"- Sampling unit: `{payload['protocol']['sampling_unit']}`",
        "",
        "## Stability Summary",
        "",
        "| Train fraction | Route row acc mean/range | Routed BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range | Routed group all-correct mean/range |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for fraction, summary in payload["summary_by_train_fraction"].items():
        route = summary["routing_row_accuracy"]
        ba = summary["learned_ba"]
        delta_single = summary["learned_minus_single_ba"]
        delta_oracle = summary["learned_minus_oracle_ba"]
        group = summary["learned_group_all_correct"]
        lines.append(
            f"| `{fraction}` | `{route['mean']} [{route['min']}, {route['max']}]` | "
            f"`{ba['mean']} [{ba['min']}, {ba['max']}]` | "
            f"`{delta_single['mean']} [{delta_single['min']}, {delta_single['max']}]` | "
            f"`{delta_oracle['mean']} [{delta_oracle['min']}, {delta_oracle['max']}]` | "
            f"`{group['mean']} [{group['min']}, {group['max']}]` |"
        )
    lines.extend(
        [
            "",
            "## Per-Source Tradeoff At Full Training Fraction",
            "",
            "| Source | Route acc mean/range | Learned BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    full_key = "1.0"
    for source, summary in payload["summary_by_train_fraction"][full_key]["per_source"].items():
        route = summary["route_accuracy"]
        ba = summary["learned_ba"]
        delta_single = summary["learned_minus_single_ba"]
        delta_oracle = summary["learned_minus_oracle_ba"]
        lines.append(
            f"| `{source}` | `{route['mean']} [{route['min']}, {route['max']}]` | "
            f"`{ba['mean']} [{ba['min']}, {ba['max']}]` | "
            f"`{delta_single['mean']} [{delta_single['min']}, {delta_single['max']}]` | "
            f"`{delta_oracle['mean']} [{delta_oracle['min']}, {delta_oracle['max']}]` |"
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


def parse_float_list(value: str) -> list[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def parse_int_list(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned content-router stability report.")
    parser.add_argument("--train-prime", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--train-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--train-patch", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-prime", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--eval-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--eval-patch", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--seeds", default="7,42,123")
    parser.add_argument("--train-fractions", default="0.5,1.0")
    parser.add_argument("--feature-mode", default="char_3_5")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_router_stability_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_ROUTER_STABILITY.md")
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
        seeds=parse_int_list(args.seeds),
        train_fractions=parse_float_list(args.train_fractions),
        max_features=args.max_features,
        feature_mode=args.feature_mode,
    )
    write_json(args.json_output, payload)
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
