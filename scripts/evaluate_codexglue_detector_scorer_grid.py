from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl, write_json
from vrf.support_scoring import evaluate_detector_scorer_grid, parse_thresholds


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

    payload = evaluate_detector_scorer_grid(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_thresholds=parse_thresholds(args.detector_thresholds),
        scorer_thresholds=parse_thresholds(args.scorer_thresholds),
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(output_path, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
