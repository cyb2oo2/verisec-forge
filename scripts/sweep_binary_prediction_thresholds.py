from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_codexglue_classifier_thresholds import compute_binary_metrics, parse_thresholds, select_best
from vrf.io_utils import read_jsonl, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Sweep thresholds over an existing binary prediction JSONL.")
    parser.add_argument("--predictions", required=True, help="JSONL with gold and vuln_probability fields")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--thresholds", default=None, help="Comma-separated thresholds")
    args = parser.parse_args()

    thresholds = parse_thresholds(args.thresholds)
    raw_rows = read_jsonl(args.predictions)
    sweep_rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        threshold_rows = [
            {
                "id": row["id"],
                "gold": int(row["gold"]),
                "pred": int(float(row["vuln_probability"]) >= threshold),
            }
            for row in raw_rows
        ]
        metrics = compute_binary_metrics(threshold_rows)
        metrics["threshold"] = round(threshold, 6)
        sweep_rows.append(metrics)

    payload = {
        "predictions": args.predictions,
        "thresholds": sweep_rows,
        "best_by_presence_accuracy": select_best(sweep_rows, "presence_accuracy"),
        "best_by_balanced_accuracy": select_best(sweep_rows, "balanced_accuracy"),
        "best_by_f1": select_best(sweep_rows, "f1"),
    }
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
