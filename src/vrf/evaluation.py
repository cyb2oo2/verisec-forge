from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any

from vrf.io_utils import read_jsonl, write_csv, write_json
from vrf.schemas import ExperimentRecord, SecureCodeEvalRow, SecureCodeGenerationRecord, SecureCodeSample
from vrf.text_utils import (
    repeated_ngram_ratio,
    safe_mean,
    security_family_label_correct,
    security_label_correct,
    security_presence_correct,
)
from vrf.tracking import log_experiment


def _index_samples(dataset_path: str) -> dict[str, SecureCodeSample]:
    return {row["id"]: SecureCodeSample.from_dict(row) for row in read_jsonl(dataset_path)}


def _load_generations(generations_path: str) -> list[SecureCodeGenerationRecord]:
    generations: list[SecureCodeGenerationRecord] = []
    for row in read_jsonl(generations_path):
        evidence = row.get("evidence", [])
        row = dict(row)
        row["evidence"] = evidence
        generations.append(SecureCodeGenerationRecord(**row))
    return generations


def evaluate_run(config: dict[str, Any], config_path: str) -> dict[str, Any]:
    samples = _index_samples(config["dataset_path"])
    generations = _load_generations(config["generations_path"])
    metrics_cfg = config.get("metrics", {})
    timeout_threshold = metrics_cfg.get("timeout_ms_threshold", 120000)
    repeat_threshold = metrics_cfg.get("repeated_reasoning_threshold", 0.2)
    repeat_ngram_size = metrics_cfg.get("repeated_reasoning_ngram_size", 3)

    rows: list[SecureCodeEvalRow] = []
    by_difficulty: dict[str, Counter[str]] = defaultdict(Counter)
    presence_correct_values: list[float] = []
    family_label_correct_values: list[float] = []
    vulnerable_recall_values: list[float] = []
    safe_specificity_values: list[float] = []

    for generation in generations:
        sample = samples[generation.id]
        presence_correct = security_presence_correct(
            generation.has_vulnerability,
            sample.has_vulnerability,
        )
        label_correct = security_label_correct(
            generation.has_vulnerability,
            generation.predicted_vulnerability_type,
            sample.has_vulnerability,
            sample.vulnerability_type,
        )
        family_label_correct = security_family_label_correct(
            generation.has_vulnerability,
            generation.predicted_vulnerability_type,
            sample.has_vulnerability,
            sample.vulnerability_type,
        )
        invalid_answer = generation.has_vulnerability is None
        timeout = generation.latency_ms > timeout_threshold
        repeated_reasoning = repeated_ngram_ratio(generation.explanation, repeat_ngram_size) >= repeat_threshold
        high_confidence_error = (
            generation.confidence is not None
            and generation.confidence >= 0.8
            and not label_correct
        )
        row = SecureCodeEvalRow(
            id=generation.id,
            task_type=sample.task_type,
            label_correct=label_correct,
            evidence_supported=generation.evidence_supported,
            explanation_supported=generation.explanation_supported,
            format_ok=generation.format_ok,
            high_confidence_error=high_confidence_error,
            invalid_output=invalid_answer or timeout,
            token_count=generation.token_count,
            difficulty=sample.difficulty,
            source=sample.source,
            language=sample.language,
            model_version=generation.model_version,
        )
        rows.append(row)
        by_difficulty[sample.difficulty]["count"] += 1
        by_difficulty[sample.difficulty]["correct"] += int(generation.label_correct)
        presence_correct_values.append(1.0 if presence_correct else 0.0)
        family_label_correct_values.append(1.0 if family_label_correct else 0.0)
        if sample.has_vulnerability is True:
            vulnerable_recall_values.append(1.0 if presence_correct else 0.0)
        if sample.has_vulnerability is False:
            safe_specificity_values.append(1.0 if presence_correct else 0.0)

    summary = {
        "num_examples": len(rows),
        "presence_accuracy": round(safe_mean(presence_correct_values), 4),
        "vulnerable_recall": round(safe_mean(vulnerable_recall_values), 4),
        "safe_specificity": round(safe_mean(safe_specificity_values), 4),
        "family_label_accuracy": round(safe_mean(family_label_correct_values), 4),
        "label_accuracy": round(safe_mean([1.0 if row.label_correct else 0.0 for row in rows]), 4),
        "evidence_support_rate": round(safe_mean([1.0 if row.evidence_supported else 0.0 for row in rows]), 4),
        "explanation_support_rate": round(safe_mean([1.0 if row.explanation_supported else 0.0 for row in rows]), 4),
        "format_pass_rate": round(safe_mean([1.0 if row.format_ok else 0.0 for row in rows]), 4),
        "avg_tokens": round(safe_mean([float(row.token_count) for row in rows]), 4),
        "invalid_output_rate": round(safe_mean([1.0 if row.invalid_output else 0.0 for row in rows]), 4),
        "high_confidence_error_rate": round(safe_mean([1.0 if row.high_confidence_error else 0.0 for row in rows]), 4),
        "repeated_explanation_rate": round(safe_mean([1.0 if repeated_reasoning else 0.0 for repeated_reasoning in [repeated_ngram_ratio(g.explanation, repeat_ngram_size) >= repeat_threshold for g in generations]]), 4),
        "avg_parse_confidence": round(safe_mean([generation.parse_confidence for generation in generations]), 4),
        "second_pass_parse_rate": round(
            safe_mean([1.0 if generation.parse_method == "second_pass_model" else 0.0 for generation in generations]),
            4,
        ),
        "safe_verifier_usage_rate": round(
            safe_mean([1.0 if getattr(generation, "verifier_used", False) else 0.0 for generation in generations]),
            4,
        ),
        "safe_verifier_override_rate": round(
            safe_mean([1.0 if getattr(generation, "verifier_overrode", False) else 0.0 for generation in generations]),
            4,
        ),
        "low_confidence_trigger_rate": round(
            safe_mean([1.0 if "low_confidence" in generation.parse_trigger else 0.0 for generation in generations]),
            4,
        ),
    }
    report = {
        "summary": summary,
        "by_difficulty": {
            difficulty: {
                "count": counter["count"],
                "accuracy": round(counter["correct"] / max(1, counter["count"]), 4),
            }
            for difficulty, counter in by_difficulty.items()
        },
        "rows": [asdict(row) for row in rows],
    }

    write_json(config["report_json_path"], report)
    write_csv(config["report_csv_path"], [asdict(row) for row in rows])

    tracker_path = config.get("tracker_path")
    if tracker_path and rows:
        log_experiment(
            ExperimentRecord(
                stage="evaluation",
                model_name=rows[0].model_version,
                config_path=config_path,
                artifact_path=config["report_json_path"],
                metrics=summary,
            ),
            tracker_path,
        )
    return report
