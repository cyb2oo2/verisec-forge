from __future__ import annotations

import argparse
from pathlib import Path

from vrf.io_utils import read_jsonl, write_json


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Build calibration and policy report for CodeXGLUE classifier probabilities.")
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    rows = read_jsonl(args.probabilities)
    buckets = [
        ("0.0-0.2", 0.0, 0.2),
        ("0.2-0.4", 0.2, 0.4),
        ("0.4-0.6", 0.4, 0.6),
        ("0.6-0.8", 0.6, 0.8),
        ("0.8-1.0", 0.8, 1.000001),
    ]
    bucket_rows = []
    total = len(rows)
    ece = 0.0

    for label, low, high in buckets:
        bucket = [row for row in rows if low <= float(row["vuln_probability"]) < high]
        if not bucket:
            bucket_rows.append(
                {
                    "bucket": label,
                    "count": 0,
                    "share": 0.0,
                    "avg_probability": 0.0,
                    "empirical_vulnerable_rate": 0.0,
                    "gap": 0.0,
                    "suggested_policy": "unused",
                }
            )
            continue

        probs = [float(row["vuln_probability"]) for row in bucket]
        empirical = mean([float(row["gold"]) for row in bucket])
        avg_prob = mean(probs)
        gap = abs(avg_prob - empirical)
        share = len(bucket) / total if total else 0.0
        ece += share * gap

        if high <= 0.4:
            policy = "recall-heavy triage if recall is critical; otherwise not trustworthy enough for conservative auditing"
        elif high <= 0.6:
            policy = "balanced review zone; strong candidate for detector-driven audit"
        elif high <= 0.8:
            policy = "specificity-favoring review zone; useful for moderate-confidence escalation"
        else:
            policy = "conservative trustworthy zone; best fit for low-false-positive auditing"

        bucket_rows.append(
            {
                "bucket": label,
                "count": len(bucket),
                "share": round(share, 4),
                "avg_probability": round(avg_prob, 4),
                "empirical_vulnerable_rate": round(empirical, 4),
                "gap": round(gap, 4),
                "suggested_policy": policy,
            }
        )

    payload = {
        "num_examples": total,
        "expected_calibration_error": round(ece, 4),
        "buckets": bucket_rows,
    }
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output_json, payload)


if __name__ == "__main__":
    main()
