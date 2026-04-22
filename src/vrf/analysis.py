from __future__ import annotations

from collections import Counter
from typing import Any

from vrf.io_utils import read_jsonl, write_json
from vrf.schemas import SecureCodeGenerationRecord, SecureCodeSample
from vrf.text_utils import security_label_correct


def _confidence_bucket(confidence: float | None) -> str:
    if confidence is None:
        return "missing"
    if confidence >= 0.9:
        return "0.9-1.0"
    if confidence >= 0.75:
        return "0.75-0.89"
    if confidence >= 0.5:
        return "0.5-0.74"
    return "0.0-0.49"


def _label_error_subtype(sample: SecureCodeSample, generation: SecureCodeGenerationRecord) -> str:
    pred_has = generation.has_vulnerability
    gold_has = sample.has_vulnerability
    if pred_has is None:
        return "null_prediction"
    if gold_has is True and pred_has is False:
        return "false_negative"
    if gold_has is False and pred_has is True:
        return "false_positive"
    if gold_has is True and pred_has is True:
        return "cwe_mismatch"
    if gold_has is False and pred_has is False:
        return "safe_label_mismatch"
    return "other_label_error"


def build_failure_analysis(config: dict[str, Any]) -> dict[str, Any]:
    samples = {row["id"]: SecureCodeSample.from_dict(row) for row in read_jsonl(config["dataset_path"])}
    generations = [SecureCodeGenerationRecord.from_dict(row) for row in read_jsonl(config["generations_path"])]

    buckets: Counter[str] = Counter()
    examples: dict[str, list[dict[str, Any]]] = {
        "correct": [],
        "format_failure": [],
        "label_failure": [],
        "evidence_failure": [],
        "explanation_failure": [],
        "high_confidence_error": [],
    }
    length_by_difficulty: dict[str, list[int]] = {}
    parse_method_counts: Counter[str] = Counter()
    parse_trigger_counts: Counter[str] = Counter()
    label_error_breakdown: Counter[str] = Counter()
    format_error_breakdown: Counter[str] = Counter()
    confidence_bucket_counts: Counter[str] = Counter()
    confidence_bucket_correct: Counter[str] = Counter()
    confidence_bucket_high_conf_error: Counter[str] = Counter()
    low_confidence_examples: list[dict[str, Any]] = []

    for generation in generations:
        sample = samples[generation.id]
        label_correct = security_label_correct(
            generation.has_vulnerability,
            generation.predicted_vulnerability_type,
            sample.has_vulnerability,
            sample.vulnerability_type,
        )
        length_by_difficulty.setdefault(sample.difficulty, []).append(generation.token_count)
        parse_method_counts[generation.parse_method] += 1
        parse_trigger_counts[generation.parse_trigger] += 1
        confidence_bucket = _confidence_bucket(generation.confidence)
        confidence_bucket_counts[confidence_bucket] += 1
        confidence_bucket_correct[confidence_bucket] += int(label_correct)
        high_confidence_error = generation.confidence is not None and generation.confidence >= 0.8 and not label_correct
        confidence_bucket_high_conf_error[confidence_bucket] += int(high_confidence_error)
        if label_correct and generation.evidence_supported and generation.explanation_supported:
            bucket = "correct"
        elif not generation.format_ok:
            bucket = "format_failure"
            format_error_breakdown[generation.parse_trigger or "unknown"] += 1
        elif high_confidence_error:
            bucket = "high_confidence_error"
        elif not label_correct:
            bucket = "label_failure"
            label_error_breakdown[_label_error_subtype(sample, generation)] += 1
        elif not generation.evidence_supported:
            bucket = "evidence_failure"
        else:
            bucket = "explanation_failure"
        buckets[bucket] += 1
        if len(examples[bucket]) < 3:
            examples[bucket].append(
                {
                    "id": generation.id,
                    "task_type": sample.task_type,
                    "prompt": sample.prompt,
                    "language": sample.language,
                    "gold_has_vulnerability": sample.has_vulnerability,
                    "gold_vulnerability_type": sample.vulnerability_type,
                    "raw_text": generation.raw_text,
                    "token_count": generation.token_count,
                    "parse_method": generation.parse_method,
                    "parse_confidence": generation.parse_confidence,
                    "parse_trigger": generation.parse_trigger,
                    "predicted_has_vulnerability": generation.has_vulnerability,
                    "predicted_vulnerability_type": generation.predicted_vulnerability_type,
                    "predicted_severity": generation.predicted_severity,
                    "label_correct": label_correct,
                    "confidence": generation.confidence,
                }
            )
        if "low_confidence" in generation.parse_trigger and len(low_confidence_examples) < 5:
            low_confidence_examples.append(
                {
                    "id": generation.id,
                    "prompt": sample.prompt,
                    "gold_has_vulnerability": sample.has_vulnerability,
                    "gold_vulnerability_type": sample.vulnerability_type,
                    "predicted_has_vulnerability": generation.has_vulnerability,
                    "predicted_vulnerability_type": generation.predicted_vulnerability_type,
                    "label_correct": label_correct,
                    "parse_method": generation.parse_method,
                    "parse_confidence": generation.parse_confidence,
                    "raw_text": generation.raw_text,
                }
            )

    report = {
        "failure_buckets": dict(buckets),
        "avg_length_by_difficulty": {
            difficulty: round(sum(lengths) / max(1, len(lengths)), 4)
            for difficulty, lengths in length_by_difficulty.items()
        },
        "parse_summary": {
            "parse_method_counts": dict(parse_method_counts),
            "parse_trigger_counts": dict(parse_trigger_counts),
            "avg_parse_confidence": round(
                sum(generation.parse_confidence for generation in generations) / max(1, len(generations)),
                4,
            ),
        },
        "label_error_breakdown": dict(label_error_breakdown),
        "format_error_breakdown": dict(format_error_breakdown),
        "confidence_summary": {
            bucket: {
                "count": confidence_bucket_counts[bucket],
                "accuracy": round(confidence_bucket_correct[bucket] / max(1, confidence_bucket_counts[bucket]), 4),
                "high_confidence_error_rate": round(
                    confidence_bucket_high_conf_error[bucket] / max(1, confidence_bucket_counts[bucket]),
                    4,
                ),
            }
            for bucket in ["0.9-1.0", "0.75-0.89", "0.5-0.74", "0.0-0.49", "missing"]
            if confidence_bucket_counts[bucket] > 0
        },
        "examples": examples,
        "low_confidence_examples": low_confidence_examples,
        "questions_answered": {
            "label_vs_evidence": "Failures are separated into label_failure, evidence_failure, and explanation_failure buckets.",
            "high_confidence_errors": "high_confidence_error examples capture confidently wrong model judgments.",
            "format_noise": "format_failure plus parse_summary indicate where benchmark instability comes from output protocol failure.",
            "parse_fallback_usage": "Use parse_summary and low_confidence_examples to inspect where second-pass extraction was triggered.",
            "misclassification_shape": "label_error_breakdown separates false positives, false negatives, and CWE mismatches.",
            "calibration_shape": "confidence_summary shows whether higher-confidence outputs are actually more reliable.",
        }
    }
    write_json(config["analysis_output_path"], report)
    return report
