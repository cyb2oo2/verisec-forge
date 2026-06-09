from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.relational_evaluation import evaluate_relational_predictions, join_predictions


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate paired relational benchmark v2 predictions."
    )
    parser.add_argument(
        "--benchmark",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument("--predictions", required=True)
    parser.add_argument(
        "--output",
        default="reports/secure_code_relational_benchmark_v2_evaluation.json",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    benchmark_rows = read_jsonl(ROOT / args.benchmark)
    prediction_rows = read_jsonl(ROOT / args.predictions)
    joined = join_predictions(benchmark_rows, prediction_rows)
    report = evaluate_relational_predictions(
        joined,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
    )
    report["benchmark"] = args.benchmark.replace("\\", "/")
    report["predictions"] = args.predictions.replace("\\", "/")
    write_json(ROOT / args.output, report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
