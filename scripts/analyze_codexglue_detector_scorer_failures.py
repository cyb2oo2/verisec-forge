from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

from evaluate_codexglue_detector_scorer import scorer_probability
from vrf.io_utils import read_jsonl, write_json


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


def safe_divide(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Break down CodeXGLUE detector + scorer failure modes.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--scorer-predictions", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--scorer-threshold", type=float, default=0.5)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = {row["id"]: row for row in read_jsonl(args.probabilities)}
    scorer_rows = {row["id"]: row for row in read_jsonl(args.scorer_predictions)}

    payload = analyze_detector_scorer_failures(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=args.threshold,
        scorer_threshold=args.scorer_threshold,
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(output_path, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
