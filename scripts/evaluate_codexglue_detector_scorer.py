from __future__ import annotations

import argparse
import json

from vrf.io_utils import read_jsonl, write_json
from vrf.support_scoring import evaluate_detector_scorer


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a CodeXGLUE detector + support scorer pipeline.")
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
