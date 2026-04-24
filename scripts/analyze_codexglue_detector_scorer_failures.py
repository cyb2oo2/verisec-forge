from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl, write_json
from vrf.support_scoring import analyze_detector_scorer_failures


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
