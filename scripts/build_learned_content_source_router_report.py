from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_content_source_router_report import (
    diff_body,
    infer_source_from_diff_body,
    infer_source_from_surface_text,
    routing_metrics,
    routing_rows,
    text_payload,
)
from scripts.build_non_oracle_source_router_report import read_jsonl

SOURCES = ["PrimeVul-time", "DeltaSecommits", "PatchEval"]


def char_ngrams(text: str, *, min_n: int = 3, max_n: int = 5, limit: int = 5000) -> Counter[str]:
    normalized = " ".join(text.lower().split())[:limit]
    counts: Counter[str] = Counter()
    for n in range(min_n, max_n + 1):
        if len(normalized) < n:
            continue
        for idx in range(0, len(normalized) - n + 1):
            counts[normalized[idx : idx + n]] += 1
    return counts


def token_ngrams(text: str, *, min_n: int = 1, max_n: int = 2, limit: int = 5000) -> Counter[str]:
    normalized = " ".join(text.lower().split())[:limit]
    tokens = re.findall(r"[a-z_][a-z0-9_]*|==|!=|<=|>=|->|::|[{}()[\].,;:+\-*/%<>=!&|]", normalized)
    counts: Counter[str] = Counter()
    for n in range(min_n, max_n + 1):
        if len(tokens) < n:
            continue
        for idx in range(0, len(tokens) - n + 1):
            counts[" ".join(tokens[idx : idx + n])] += 1
    return counts


def diff_line_markers(text: str, *, limit: int = 5000) -> Counter[str]:
    counts: Counter[str] = Counter()
    for raw_line in text[:limit].splitlines():
        line = raw_line.strip().lower()
        if not line:
            continue
        prefix = line[:1] if line[:1] in {"+", "-", "@"} else "context"
        counts[f"line_prefix={prefix}"] += 1
        for token in re.findall(r"[a-z_][a-z0-9_]*|==|!=|<=|>=|->|::", line)[:8]:
            counts[f"{prefix}:{token}"] += 1
    return counts


def feature_counts(text: str, *, feature_mode: str = "char_3_5") -> Counter[str]:
    if feature_mode == "char_3_5":
        return char_ngrams(text)
    if feature_mode == "token_1_2":
        return token_ngrams(text)
    if feature_mode == "diff_line_markers":
        return diff_line_markers(text)
    raise ValueError(f"Unsupported feature mode: {feature_mode}")


def input_text(row: dict[str, Any], mode: str) -> str:
    text = text_payload(row)
    if mode == "surface":
        return text
    if mode == "diff_body":
        return diff_body(text)
    raise ValueError(f"Unsupported mode: {mode}")


def examples(metadata_by_source: dict[str, list[dict[str, Any]]], *, mode: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for source, metadata_rows in metadata_by_source.items():
        for row in metadata_rows:
            rows.append(
                {
                    "true_source": source,
                    "pair_key": str(row.get("pair_key") or row.get("id")),
                    "text": input_text(row, mode),
                }
            )
    return rows


def select_vocabulary(train_examples: list[dict[str, str]], *, max_features: int, feature_mode: str = "char_3_5") -> set[str]:
    doc_freq: Counter[str] = Counter()
    for row in train_examples:
        doc_freq.update(feature_counts(row["text"], feature_mode=feature_mode).keys())
    return {feature for feature, _count in doc_freq.most_common(max_features)}


def train_nb(
    train_examples: list[dict[str, str]],
    *,
    max_features: int = 50000,
    alpha: float = 1.0,
    classes: list[str] | None = None,
    feature_mode: str = "char_3_5",
) -> dict[str, Any]:
    class_names = classes or SOURCES
    vocab = select_vocabulary(train_examples, max_features=max_features, feature_mode=feature_mode)
    class_doc_counts: Counter[str] = Counter()
    token_counts: dict[str, Counter[str]] = {source: Counter() for source in class_names}
    token_totals: Counter[str] = Counter()
    for row in train_examples:
        source = row["true_source"]
        if source not in token_counts:
            raise ValueError(f"Training example source {source!r} is not in classes: {class_names}")
        class_doc_counts[source] += 1
        features = feature_counts(row["text"], feature_mode=feature_mode)
        for feature, count in features.items():
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
            source: math.log((class_doc_counts[source] + alpha) / (total_docs + alpha * len(class_names))) for source in class_names
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


def predict_one(model: dict[str, Any], text: str) -> str:
    features = feature_counts(text, feature_mode=str(model.get("feature_mode", "char_3_5")))
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


def predict_rows(model: dict[str, Any], eval_examples: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "true_source": row["true_source"],
            "predicted_source": predict_one(model, row["text"]),
            "pair_key": row["pair_key"],
        }
        for row in eval_examples
    ]


def build_report(
    *,
    train_prime_metadata: list[dict[str, Any]],
    train_delta_metadata: list[dict[str, Any]],
    train_patch_metadata: list[dict[str, Any]],
    eval_prime_metadata: list[dict[str, Any]],
    eval_delta_metadata: list[dict[str, Any]],
    eval_patch_metadata: list[dict[str, Any]],
    max_features: int = 50000,
) -> dict[str, Any]:
    train_by_source = {
        "PrimeVul-time": train_prime_metadata,
        "DeltaSecommits": train_delta_metadata,
        "PatchEval": train_patch_metadata,
    }
    eval_by_source = {
        "PrimeVul-time": eval_prime_metadata,
        "DeltaSecommits": eval_delta_metadata,
        "PatchEval": eval_patch_metadata,
    }
    surface_train = examples(train_by_source, mode="surface")
    surface_eval = examples(eval_by_source, mode="surface")
    diff_train = examples(train_by_source, mode="diff_body")
    diff_eval = examples(eval_by_source, mode="diff_body")
    surface_model = train_nb(surface_train, max_features=max_features)
    diff_model = train_nb(diff_train, max_features=max_features)
    heuristic_surface = routing_metrics(routing_rows(eval_by_source, infer_source_from_surface_text))
    heuristic_diff = routing_metrics(routing_rows(eval_by_source, infer_source_from_diff_body))
    learned_surface = routing_metrics(predict_rows(surface_model, surface_eval))
    learned_diff = routing_metrics(predict_rows(diff_model, diff_eval))
    return {
        "status": "ok",
        "scope": "learned_content_source_router",
        "protocol": {
            "model": "character n-gram multinomial naive bayes",
            "max_features": max_features,
            "inputs": {
                "surface": "pair_text/prompt content only",
                "diff_body": "text after Unified diff marker only",
            },
            "forbidden_row_fields": [
                "source_dataset",
                "id",
                "pair_key",
                "programming_language",
                "file_extension",
                "file_path",
                "patch_url",
            ],
            "train_rows": {source: len(rows) for source, rows in train_by_source.items()},
            "eval_rows": {source: len(rows) for source, rows in eval_by_source.items()},
        },
        "routing_metrics": {
            "heuristic_surface": heuristic_surface,
            "heuristic_diff_body": heuristic_diff,
            "learned_surface": learned_surface,
            "learned_diff_body": learned_diff,
        },
        "model_stats": {
            "surface": {
                "vocab_size": surface_model["vocab_size"],
                "train_doc_counts": surface_model["train_doc_counts"],
            },
            "diff_body": {
                "vocab_size": diff_model["vocab_size"],
                "train_doc_counts": diff_model["train_doc_counts"],
            },
        },
        "conclusion": (
            "The learned character n-gram router establishes a dependency-free content-routing baseline. "
            "Surface routing tests whether visible prompt content can select experts; diff-body routing is the stricter check for code-diff-only expert selection."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Content Source Router",
        "",
        "This report trains a lightweight character n-gram Naive Bayes router for source/expert selection.",
        "",
        "## Protocol",
        "",
        f"- Model: `{payload['protocol']['model']}`",
        f"- Max features: `{payload['protocol']['max_features']}`",
        f"- Forbidden row fields: `{', '.join(payload['protocol']['forbidden_row_fields'])}`",
        "",
        "## Routing Results",
        "",
        "| Router | Row Accuracy | Pair Accuracy | PrimeVul Acc | Delta Acc | PatchEval Acc |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, metrics in payload["routing_metrics"].items():
        by_source = metrics["by_source"]
        lines.append(
            f"| `{name}` | `{metrics['row_accuracy']}` | `{metrics['pair_group_accuracy']}` | "
            f"`{by_source['PrimeVul-time']['accuracy']}` | `{by_source['DeltaSecommits']['accuracy']}` | "
            f"`{by_source['PatchEval']['accuracy']}` |"
        )
    lines.extend(
        [
            "",
            "## Model Stats",
            "",
            f"- Surface vocab size: `{payload['model_stats']['surface']['vocab_size']}`",
            f"- Diff-body vocab size: `{payload['model_stats']['diff_body']['vocab_size']}`",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned content source-router report.")
    parser.add_argument("--train-prime", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--train-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--train-patch", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-prime", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--eval-delta", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--eval-patch", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--json-output", default="reports/secure_code_learned_content_source_router_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_CONTENT_SOURCE_ROUTER.md")
    args = parser.parse_args()

    payload = build_report(
        train_prime_metadata=read_jsonl(args.train_prime),
        train_delta_metadata=read_jsonl(args.train_delta),
        train_patch_metadata=read_jsonl(args.train_patch),
        eval_prime_metadata=read_jsonl(args.eval_prime),
        eval_delta_metadata=read_jsonl(args.eval_delta),
        eval_patch_metadata=read_jsonl(args.eval_patch),
        max_features=args.max_features,
    )
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
