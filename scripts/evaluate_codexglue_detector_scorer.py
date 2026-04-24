from __future__ import annotations

import argparse
import json

from vrf.io_utils import read_jsonl, write_json


def scorer_probability(row: dict) -> float:
    if "supported_probability" in row:
        return float(row["supported_probability"])
    if "vuln_probability" in row:
        return float(row["vuln_probability"])
    return float(row.get("pred", 0))


def evaluate_detector_scorer(
    *,
    dataset_rows: dict[str, dict],
    probability_rows: dict[str, dict],
    scorer_rows: dict[str, dict],
    detector_threshold: float,
    scorer_threshold: float,
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
        "detector_positive_rate": round(detector_positive / len(dataset_rows), 4) if dataset_rows else 0.0,
        "scorer_positive_rate": round(scorer_positive / len(dataset_rows), 4) if dataset_rows else 0.0,
        "unsupported_positive_share": round(fp / scorer_positive, 4) if scorer_positive else 0.0,
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a CodeXGLUE detector + evidence scorer pipeline.")
    parser.add_argument("--dataset", required=True, help="Full CodeXGLUE eval dataset")
    parser.add_argument("--probabilities", required=True, help="Detector probability jsonl for the full eval split")
    parser.add_argument("--scorer-predictions", required=True, help="Scorer predictions on detector-positive traffic")
    parser.add_argument("--threshold", type=float, default=0.5, help="Detector threshold used to route positive traffic")
    parser.add_argument("--scorer-threshold", type=float, default=0.5, help="Scorer probability threshold")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = {row["id"]: row for row in read_jsonl(args.probabilities)}
    scorer_rows = {row["id"]: row for row in read_jsonl(args.scorer_predictions)}

    payload = evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=args.threshold,
        scorer_threshold=args.scorer_threshold,
    )
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
