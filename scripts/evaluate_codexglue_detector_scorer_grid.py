from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluate_codexglue_detector_scorer import evaluate_detector_scorer
from vrf.io_utils import read_jsonl, write_json


def parse_thresholds(value: str) -> list[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a detector/scorer threshold grid on CodeXGLUE.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--scorer-predictions", required=True, help="Scorer predictions for a superset of detector-positive traffic")
    parser.add_argument("--detector-thresholds", default="0.2,0.5,0.8")
    parser.add_argument("--scorer-thresholds", default="0.2,0.5,0.8")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = {row["id"]: row for row in read_jsonl(args.probabilities)}
    scorer_rows = {row["id"]: row for row in read_jsonl(args.scorer_predictions)}

    results: list[dict] = []
    for detector_threshold in parse_thresholds(args.detector_thresholds):
        for scorer_threshold in parse_thresholds(args.scorer_thresholds):
            results.append(
                evaluate_detector_scorer(
                    dataset_rows=dataset_rows,
                    probability_rows=probability_rows,
                    scorer_rows=scorer_rows,
                    detector_threshold=detector_threshold,
                    scorer_threshold=scorer_threshold,
                )
            )

    payload = {
        "results": results,
        "best_by_presence_accuracy": max(results, key=lambda row: (row["presence_accuracy"], row["f1"])),
        "best_by_f1": max(results, key=lambda row: (row["f1"], row["presence_accuracy"])),
        "best_by_precision": max(results, key=lambda row: (row["precision"], row["f1"])),
        "best_by_recall": max(results, key=lambda row: (row["vulnerable_recall"], row["f1"])),
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(output_path, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
