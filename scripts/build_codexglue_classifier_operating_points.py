from __future__ import annotations

import argparse
from pathlib import Path

from vrf.io_utils import read_json, write_json, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Build thresholded classifier prediction files from probability outputs.")
    parser.add_argument("--threshold-report", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--thresholds", default=None, help="Comma-separated thresholds to export. Defaults to best accuracy/f1 plus 0.5.")
    args = parser.parse_args()

    threshold_report = read_json(args.threshold_report)
    probabilities = read_json(args.probabilities) if str(args.probabilities).endswith(".json") else None
    if probabilities is None:
        from vrf.io_utils import read_jsonl

        probability_rows = read_jsonl(args.probabilities)
    else:
        probability_rows = probabilities

    requested = []
    if args.thresholds:
        requested = [float(item.strip()) for item in args.thresholds.split(",") if item.strip()]
    else:
        requested = sorted(
            {
                0.5,
                float(threshold_report["best_by_presence_accuracy"]["threshold"]),
                float(threshold_report["best_by_f1"]["threshold"]),
            }
        )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    exported = []
    for threshold in requested:
        rows = []
        for row in probability_rows:
            rows.append(
                {
                    "id": row["id"],
                    "gold": row["gold"],
                    "pred": int(float(row["vuln_probability"]) >= threshold),
                    "vuln_probability": row["vuln_probability"],
                    "threshold": threshold,
                }
            )
        threshold_tag = str(threshold).replace(".", "p")
        output_path = output_dir / f"secure_code_codexglue_cls_threshold_{threshold_tag}_predictions.jsonl"
        write_jsonl(output_path, rows)
        exported.append({"threshold": threshold, "path": str(output_path)})

    write_json(output_dir / "exported_thresholds.json", {"thresholds": exported})


if __name__ == "__main__":
    main()
