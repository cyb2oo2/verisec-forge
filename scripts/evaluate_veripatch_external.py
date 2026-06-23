from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.external_adapter import (
    build_prediction_template,
    evaluate_external_predictions,
    validate_external_predictions,
)
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate externally supplied predictions on a VeriPatch-RR "
            "benchmark artifact."
        )
    )
    parser.add_argument(
        "--benchmark",
        default="examples/veripatch_rr_smoke_30.jsonl",
    )
    parser.add_argument("--predictions")
    parser.add_argument(
        "--output",
        default="reports/veripatch_rr_external_eval.json",
    )
    parser.add_argument("--write-template")
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    benchmark_rows = read_jsonl(ROOT / args.benchmark)
    if args.write_template:
        write_jsonl(
            ROOT / args.write_template,
            build_prediction_template(benchmark_rows),
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "template": args.write_template,
                    "rows": len(benchmark_rows),
                },
                indent=2,
            )
        )
        return 0

    if not args.predictions:
        parser.error("provide --predictions or --write-template")

    prediction_rows = read_jsonl(ROOT / args.predictions)
    validation = validate_external_predictions(benchmark_rows, prediction_rows)
    if validation["status"] != "ok":
        report = {
            "status": "error",
            "benchmark": args.benchmark.replace("\\", "/"),
            "predictions": args.predictions.replace("\\", "/"),
            "validation": validation,
        }
        write_json(ROOT / args.output, report)
        print(json.dumps(report, indent=2))
        return 2

    report = evaluate_external_predictions(
        benchmark_rows,
        prediction_rows,
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
