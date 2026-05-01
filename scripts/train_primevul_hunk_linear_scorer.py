from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_primevul_hunk_pseudo_label_dataset import coverage_at_k
from vrf.io_utils import read_jsonl, write_json, write_jsonl


FEATURE_NAMES = [
    "bias",
    "hunk_rank_inverse",
    "changed_lines",
    "added_lines",
    "removed_lines",
    "risk_support",
    "safety_support",
    "net_risk_support",
    "protection_delta",
    "risk_delta",
    "safer_delta",
    "direction_unclear",
    "candidate_adds_protection",
    "candidate_removes_protection",
    "candidate_introduces_risk",
    "candidate_removes_risk",
    "keyword_count",
]

SIDE_AWARE_FEATURE_NAMES = [
    *FEATURE_NAMES,
    "side_is_vulnerable",
    "aligned_support",
    "opposing_support",
    "alignment_margin",
    "aligned_protection_delta",
    "aligned_risk_delta",
    "aligned_safer_delta",
]


def feature_names(*, side_aware: bool) -> list[str]:
    return SIDE_AWARE_FEATURE_NAMES if side_aware else FEATURE_NAMES


def features(row: dict[str, Any], *, side_aware: bool = False) -> dict[str, float]:
    labels = set(row.get("direction_labels") or [])
    hunk_rank = max(1, int(row.get("hunk_rank") or 1))
    values = {
        "bias": 1.0,
        "hunk_rank_inverse": 1.0 / hunk_rank,
        "changed_lines": math.log1p(float(row.get("changed_lines") or 0)),
        "added_lines": math.log1p(float(row.get("added_lines") or 0)),
        "removed_lines": math.log1p(float(row.get("removed_lines") or 0)),
        "risk_support": float(row.get("risk_support") or 0),
        "safety_support": float(row.get("safety_support") or 0),
        "net_risk_support": float(row.get("net_risk_support") or 0),
        "protection_delta": float(row.get("protection_delta") or 0),
        "risk_delta": float(row.get("risk_delta") or 0),
        "safer_delta": float(row.get("safer_delta") or 0),
        "direction_unclear": float("direction_unclear" in labels),
        "candidate_adds_protection": float("candidate_adds_protection" in labels),
        "candidate_removes_protection": float("candidate_removes_protection" in labels),
        "candidate_introduces_risk": float("candidate_introduces_risk" in labels),
        "candidate_removes_risk": float("candidate_removes_risk" in labels),
        "keyword_count": float(len(row.get("keywords") or [])),
    }
    if side_aware:
        side_is_vulnerable = int(row.get("decision_side", row.get("gold", 1))) == 1
        risk_support = values["risk_support"]
        safety_support = values["safety_support"]
        protection_delta = values["protection_delta"]
        risk_delta = values["risk_delta"]
        safer_delta = values["safer_delta"]
        aligned_support = risk_support if side_is_vulnerable else safety_support
        opposing_support = safety_support if side_is_vulnerable else risk_support
        values.update(
            {
                "side_is_vulnerable": float(side_is_vulnerable),
                "aligned_support": aligned_support,
                "opposing_support": opposing_support,
                "alignment_margin": aligned_support - opposing_support,
                "aligned_protection_delta": -protection_delta if side_is_vulnerable else protection_delta,
                "aligned_risk_delta": risk_delta if side_is_vulnerable else -risk_delta,
                "aligned_safer_delta": -safer_delta if side_is_vulnerable else safer_delta,
            }
        )
    return values


def dot(weights: dict[str, float], row_features: dict[str, float], *, side_aware: bool = False) -> float:
    return sum(weights.get(name, 0.0) * row_features.get(name, 0.0) for name in feature_names(side_aware=side_aware))


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def train_linear_scorer(
    rows: list[dict[str, Any]],
    *,
    epochs: int,
    learning_rate: float,
    l2: float,
    seed: int,
    side_aware: bool = False,
) -> dict[str, float]:
    rng = random.Random(seed)
    names = feature_names(side_aware=side_aware)
    weights = {name: 0.0 for name in names}
    training_rows = list(rows)
    for _epoch in range(epochs):
        rng.shuffle(training_rows)
        for row in training_rows:
            label = float(int(row["pseudo_label"]))
            row_features = features(row, side_aware=side_aware)
            prediction = sigmoid(dot(weights, row_features, side_aware=side_aware))
            error = prediction - label
            for name in names:
                weights[name] -= learning_rate * (error * row_features.get(name, 0.0) + l2 * weights[name])
    return weights


def score_rows(rows: list[dict[str, Any]], weights: dict[str, float], *, side_aware: bool = False, score_prefix: str = "linear") -> list[dict[str, Any]]:
    scored = []
    for row in rows:
        raw_score = dot(weights, features(row, side_aware=side_aware), side_aware=side_aware)
        scored.append(
            {
                **row,
                f"{score_prefix}_score": raw_score,
                f"{score_prefix}_probability": sigmoid(raw_score),
            }
        )
    return scored


def coverage_at_k_by_score(rows: list[dict[str, Any]], *, k: int, score_key: str) -> dict[str, Any]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["source_id"])].append(row)
    reranked: list[dict[str, Any]] = []
    for group in grouped.values():
        ordered = sorted(group, key=lambda row: score_value(row, score_key), reverse=True)
        for rank, row in enumerate(ordered, start=1):
            reranked.append({**row, "hunk_rank": rank})
    result = coverage_at_k(reranked, k=k)
    result["score_key"] = score_key
    return result


def score_value(row: dict[str, Any], score_key: str) -> float:
    if score_key == "hunk_rank_inverse":
        return 1.0 / max(1, int(row.get("hunk_rank") or 1))
    return float(row[score_key])


def evaluate(rows: list[dict[str, Any]], *, k_values: list[int], score_key: str) -> list[dict[str, Any]]:
    return [coverage_at_k_by_score(rows, k=k, score_key=score_key) for k in k_values]


def label_metrics(rows: list[dict[str, Any]], *, probability_key: str = "linear_probability") -> dict[str, Any]:
    total = len(rows)
    positives = sum(1 for row in rows if int(row["pseudo_label"]) == 1)
    predicted = sum(1 for row in rows if float(row[probability_key]) >= 0.5)
    tp = sum(1 for row in rows if int(row["pseudo_label"]) == 1 and float(row[probability_key]) >= 0.5)
    fp = sum(1 for row in rows if int(row["pseudo_label"]) == 0 and float(row[probability_key]) >= 0.5)
    fn = positives - tp
    tn = total - positives - fp
    precision = tp / predicted if predicted else 0.0
    recall = tp / positives if positives else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return {
        "rows": total,
        "positive_rate": round(positives / total, 4) if total else 0.0,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Hunk Linear Scorer",
        "",
        "This report trains a dependency-free linear hunk scorer on pseudo labels. It is a cheap sanity baseline before heavier evidence-localizer training.",
        "",
        "## Label Metrics",
        "",
        f"- Train accuracy: `{payload['train_label_metrics']['accuracy']}`",
        f"- Eval accuracy: `{payload['eval_label_metrics']['accuracy']}`",
        f"- Eval precision/recall/specificity: `{payload['eval_label_metrics']['precision']}` / `{payload['eval_label_metrics']['recall']}` / `{payload['eval_label_metrics']['specificity']}`",
        f"- Side-aware eval accuracy: `{payload['side_aware_eval_label_metrics']['accuracy']}`",
        f"- Side-aware eval precision/recall/specificity: `{payload['side_aware_eval_label_metrics']['precision']}` / `{payload['side_aware_eval_label_metrics']['recall']}` / `{payload['side_aware_eval_label_metrics']['specificity']}`",
        "",
        "## Top-K Coverage",
        "",
        "| split | scorer | k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for split_name in ["train", "eval"]:
        for scorer_name, rows in payload[f"{split_name}_coverage"].items():
            for row in rows:
                lines.append(
                    f"| {split_name} | {scorer_name} | {row['k']} | {row['coverage']} | {row['vulnerable_coverage']} | {row['safe_coverage']} | {row['covered_rows']} | {row['rows']} |"
                )
    lines.extend(
        [
            "",
            "## Learned Weights",
            "",
        ]
    )
    for name, value in payload["weights_ranked"]:
        lines.append(f"- `{name}`: `{value}`")
    if payload.get("side_aware_weights_ranked"):
        lines.extend(["", "## Side-Aware Learned Weights", ""])
        for name, value in payload["side_aware_weights_ranked"]:
            lines.append(f"- `{name}`: `{value}`")
    lines.append("")
    return "\n".join(lines)


def parse_ints(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def build_report(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    k_values: list[int],
    epochs: int,
    learning_rate: float,
    l2: float,
    seed: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    weights = train_linear_scorer(train_rows, epochs=epochs, learning_rate=learning_rate, l2=l2, seed=seed)
    side_aware_weights = train_linear_scorer(
        train_rows,
        epochs=epochs,
        learning_rate=learning_rate,
        l2=l2,
        seed=seed,
        side_aware=True,
    )
    scored_train = score_rows(train_rows, weights)
    scored_eval = score_rows(eval_rows, weights)
    side_aware_scored_train = score_rows(train_rows, side_aware_weights, side_aware=True, score_prefix="side_aware_linear")
    side_aware_scored_eval = score_rows(eval_rows, side_aware_weights, side_aware=True, score_prefix="side_aware_linear")
    combined_scored_eval = [
        {
            **linear_row,
            "side_aware_linear_score": side_row["side_aware_linear_score"],
            "side_aware_linear_probability": side_row["side_aware_linear_probability"],
        }
        for linear_row, side_row in zip(scored_eval, side_aware_scored_eval, strict=True)
    ]
    payload = {
        "config": {
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "seed": seed,
            "k_values": k_values,
        },
        "train_label_metrics": label_metrics(scored_train),
        "eval_label_metrics": label_metrics(scored_eval),
        "side_aware_train_label_metrics": label_metrics(side_aware_scored_train, probability_key="side_aware_linear_probability"),
        "side_aware_eval_label_metrics": label_metrics(side_aware_scored_eval, probability_key="side_aware_linear_probability"),
        "train_coverage": {
            "keyword_rank": evaluate(train_rows, k_values=k_values, score_key="hunk_rank_inverse"),
            "linear_scorer": evaluate(scored_train, k_values=k_values, score_key="linear_score"),
            "side_aware_linear_scorer": evaluate(side_aware_scored_train, k_values=k_values, score_key="side_aware_linear_score"),
        },
        "eval_coverage": {
            "keyword_rank": evaluate(eval_rows, k_values=k_values, score_key="hunk_rank_inverse"),
            "linear_scorer": evaluate(scored_eval, k_values=k_values, score_key="linear_score"),
            "side_aware_linear_scorer": evaluate(side_aware_scored_eval, k_values=k_values, score_key="side_aware_linear_score"),
        },
        "weights": {name: round(value, 6) for name, value in weights.items()},
        "side_aware_weights": {name: round(value, 6) for name, value in side_aware_weights.items()},
        "weights_ranked": [
            [name, round(value, 6)]
            for name, value in sorted(weights.items(), key=lambda item: abs(item[1]), reverse=True)
        ],
        "side_aware_weights_ranked": [
            [name, round(value, 6)]
            for name, value in sorted(side_aware_weights.items(), key=lambda item: abs(item[1]), reverse=True)
        ],
    }
    return payload, combined_scored_eval


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate a lightweight PrimeVul hunk scorer.")
    parser.add_argument("--train", required=True)
    parser.add_argument("--eval", required=True)
    parser.add_argument("--k-values", default="1,2,3,5,8")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--learning-rate", type=float, default=0.02)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    parser.add_argument("--scored-eval-output")
    args = parser.parse_args()

    payload, scored_eval = build_report(
        read_jsonl(args.train),
        read_jsonl(args.eval),
        k_values=parse_ints(args.k_values),
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        seed=args.seed,
    )
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    if args.scored_eval_output:
        write_jsonl(args.scored_eval_output, scored_eval)
    print(json.dumps(payload["eval_coverage"], indent=2))


if __name__ == "__main__":
    main()
