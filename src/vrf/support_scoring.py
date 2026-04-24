from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean


def parse_thresholds(value: str) -> list[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def scorer_probability(row: dict) -> float:
    if "supported_probability" in row:
        return float(row["supported_probability"])
    if "vuln_probability" in row:
        return float(row["vuln_probability"])
    return float(row.get("pred", 0))


def safe_divide(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def evaluate_detector_scorer(
    *,
    dataset_rows: dict[str, dict],
    probability_rows: dict[str, dict],
    scorer_rows: dict[str, dict],
    detector_threshold: float,
    scorer_threshold: float = 0.5,
) -> dict:
    tp = tn = fp = fn = 0
    detector_positive = 0
    scorer_positive = 0

    vulnerable_total = sum(bool(row.get("has_vulnerability")) for row in dataset_rows.values())
    safe_total = len(dataset_rows) - vulnerable_total

    for sample_id, sample in dataset_rows.items():
        detector_prob = float(probability_rows[sample_id]["vuln_probability"])
        detector_has = detector_prob >= detector_threshold
        pred_has = False
        if detector_has:
            detector_positive += 1
            scorer = scorer_rows.get(sample_id)
            if scorer is not None and scorer_probability(scorer) >= scorer_threshold:
                pred_has = True
                scorer_positive += 1

        gold_has = bool(sample.get("has_vulnerability"))
        if pred_has and gold_has:
            tp += 1
        elif pred_has and not gold_has:
            fp += 1
        elif (not pred_has) and gold_has:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    vulnerable_recall = tp / vulnerable_total if vulnerable_total else 0.0
    safe_specificity = tn / safe_total if safe_total else 0.0
    presence_accuracy = (tp + tn) / len(dataset_rows) if dataset_rows else 0.0
    f1 = (2 * precision * vulnerable_recall / (precision + vulnerable_recall)) if (precision + vulnerable_recall) else 0.0

    return {
        "num_examples": len(dataset_rows),
        "detector_threshold": detector_threshold,
        "scorer_threshold": scorer_threshold,
        "detector_positive_rate": safe_divide(detector_positive, len(dataset_rows)),
        "scorer_positive_rate": safe_divide(scorer_positive, len(dataset_rows)),
        "unsupported_positive_share": safe_divide(fp, scorer_positive),
        "presence_accuracy": round(presence_accuracy, 4),
        "vulnerable_recall": round(vulnerable_recall, 4),
        "safe_specificity": round(safe_specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def evaluate_detector_scorer_grid(
    *,
    dataset_rows: dict[str, dict],
    probability_rows: dict[str, dict],
    scorer_rows: dict[str, dict],
    detector_thresholds: list[float],
    scorer_thresholds: list[float],
) -> dict:
    results: list[dict] = []
    for detector_threshold in detector_thresholds:
        for scorer_threshold in scorer_thresholds:
            results.append(
                evaluate_detector_scorer(
                    dataset_rows=dataset_rows,
                    probability_rows=probability_rows,
                    scorer_rows=scorer_rows,
                    detector_threshold=detector_threshold,
                    scorer_threshold=scorer_threshold,
                )
            )

    return {
        "results": results,
        "best_by_presence_accuracy": max(results, key=lambda row: (row["presence_accuracy"], row["f1"])),
        "best_by_f1": max(results, key=lambda row: (row["f1"], row["presence_accuracy"])),
        "best_by_precision": max(results, key=lambda row: (row["precision"], row["f1"])),
        "best_by_recall": max(results, key=lambda row: (row["vulnerable_recall"], row["f1"])),
    }


def bucket_prediction(*, gold_has: bool, detector_has: bool, scorer_has: bool) -> str:
    if gold_has and detector_has and scorer_has:
        return "true_positive_supported"
    if gold_has and not detector_has:
        return "false_negative_detector_miss"
    if gold_has and detector_has and not scorer_has:
        return "false_negative_scorer_reject"
    if (not gold_has) and detector_has and scorer_has:
        return "false_positive_supported_safe"
    if (not gold_has) and detector_has and not scorer_has:
        return "true_negative_scorer_reject"
    return "true_negative_detector_reject"


def analyze_detector_scorer_failures(
    *,
    dataset_rows: dict[str, dict],
    probability_rows: dict[str, dict],
    scorer_rows: dict[str, dict],
    detector_threshold: float,
    scorer_threshold: float,
) -> dict:
    counts: Counter[str] = Counter()
    detector_probabilities: defaultdict[str, list[float]] = defaultdict(list)
    scorer_probabilities: defaultdict[str, list[float]] = defaultdict(list)
    missing_scorer_predictions = 0

    for sample_id, sample in dataset_rows.items():
        detector_probability = float(probability_rows[sample_id]["vuln_probability"])
        detector_has = detector_probability >= detector_threshold
        scorer_row = scorer_rows.get(sample_id)
        scorer_has = False
        scorer_prob: float | None = None
        if detector_has:
            if scorer_row is None:
                missing_scorer_predictions += 1
            else:
                scorer_prob = scorer_probability(scorer_row)
                scorer_has = scorer_prob >= scorer_threshold

        gold_has = bool(sample.get("has_vulnerability"))
        bucket = bucket_prediction(gold_has=gold_has, detector_has=detector_has, scorer_has=scorer_has)
        counts[bucket] += 1
        detector_probabilities[bucket].append(detector_probability)
        if scorer_prob is not None:
            scorer_probabilities[bucket].append(scorer_prob)

    tp = counts["true_positive_supported"]
    fp = counts["false_positive_supported_safe"]
    fn = counts["false_negative_detector_miss"] + counts["false_negative_scorer_reject"]
    tn = counts["true_negative_detector_reject"] + counts["true_negative_scorer_reject"]
    vulnerable_total = tp + fn
    safe_total = fp + tn
    scorer_positive = tp + fp
    total = len(dataset_rows)

    bucket_probability_summary = {}
    for bucket, bucket_count in sorted(counts.items()):
        bucket_probability_summary[bucket] = {
            "count": bucket_count,
            "avg_detector_probability": round(mean(detector_probabilities[bucket]), 4),
            "avg_scorer_probability": round(mean(scorer_probabilities[bucket]), 4)
            if scorer_probabilities[bucket]
            else None,
        }

    return {
        "num_examples": total,
        "detector_threshold": detector_threshold,
        "scorer_threshold": scorer_threshold,
        "missing_scorer_predictions": missing_scorer_predictions,
        "counts": dict(sorted(counts.items())),
        "rates": {
            "presence_accuracy": safe_divide(tp + tn, total),
            "vulnerable_recall": safe_divide(tp, vulnerable_total),
            "safe_specificity": safe_divide(tn, safe_total),
            "precision": safe_divide(tp, scorer_positive),
            "unsupported_positive_share": safe_divide(fp, scorer_positive),
            "false_negative_detector_miss_share": safe_divide(counts["false_negative_detector_miss"], fn),
            "false_negative_scorer_reject_share": safe_divide(counts["false_negative_scorer_reject"], fn),
            "true_negative_detector_reject_share": safe_divide(counts["true_negative_detector_reject"], tn),
            "true_negative_scorer_reject_share": safe_divide(counts["true_negative_scorer_reject"], tn),
        },
        "bucket_probability_summary": bucket_probability_summary,
    }
