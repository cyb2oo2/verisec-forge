from __future__ import annotations

import argparse
import json

from vrf.io_utils import read_jsonl, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a PrimeVul detector + evidence confirmer pipeline.")
    parser.add_argument("--dataset", required=True, help="Full PrimeVul holdout dataset")
    parser.add_argument("--probabilities", required=True, help="Detector probability jsonl for the full holdout")
    parser.add_argument("--confirmer-generations", required=True, help="Confirmer generations on detector-positive traffic")
    parser.add_argument("--threshold", type=float, default=0.5, help="Detector threshold used to route positive traffic")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = {row["id"]: row for row in read_jsonl(args.probabilities)}
    confirmer_rows = {row["id"]: row for row in read_jsonl(args.confirmer_generations)}

    tp = tn = fp = fn = 0
    detector_positive = 0
    confirmer_positive = 0
    confirmer_positive_with_evidence = 0
    unsupported_positive = 0

    vulnerable_total = sum(bool(row.get("has_vulnerability")) for row in dataset_rows.values())
    safe_total = len(dataset_rows) - vulnerable_total

    for sample_id, sample in dataset_rows.items():
        detector_prob = float(probability_rows[sample_id]["vuln_probability"])
        detector_has = detector_prob >= args.threshold
        pred_has = False
        evidence_supported = False

        if detector_has:
            detector_positive += 1
            confirmer = confirmer_rows.get(sample_id)
            if confirmer is not None:
                pred_has = bool(confirmer.get("has_vulnerability"))
                evidence_supported = bool(confirmer.get("evidence"))
                if pred_has:
                    confirmer_positive += 1
                    if evidence_supported:
                        confirmer_positive_with_evidence += 1
                    else:
                        unsupported_positive += 1

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

    payload = {
        "num_examples": len(dataset_rows),
        "threshold": args.threshold,
        "detector_positive_rate": round(detector_positive / len(dataset_rows), 4) if dataset_rows else 0.0,
        "confirmer_positive_rate": round(confirmer_positive / len(dataset_rows), 4) if dataset_rows else 0.0,
        "unsupported_positive_share": round(unsupported_positive / confirmer_positive, 4) if confirmer_positive else 0.0,
        "avg_evidence_items_per_positive": round(
            sum(len(row.get("evidence", [])) for row in confirmer_rows.values() if bool(row.get("has_vulnerability")))
            / max(1, confirmer_positive),
            4,
        ),
        "presence_accuracy": round(presence_accuracy, 4),
        "vulnerable_recall": round(vulnerable_recall, 4),
        "safe_specificity": round(safe_specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "confirmer_positive_with_evidence": confirmer_positive_with_evidence,
    }
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
