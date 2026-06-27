from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.relation_consistent_decoding import relation_consistent_decode
from vrf.relational_evaluation import evaluate_relational_predictions, join_predictions


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply deterministic relation-consistent decoding to existing "
            "VeriPatch-RR predictions."
        )
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report-output", required=True)
    parser.add_argument("--evaluation-output")
    parser.add_argument("--minimum-candidates", type=int, default=1)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    benchmark_rows = read_jsonl(ROOT / args.benchmark)
    prediction_rows = read_jsonl(ROOT / args.predictions)
    decoded_rows, report = relation_consistent_decode(
        benchmark_rows,
        prediction_rows,
        minimum_candidates=args.minimum_candidates,
    )

    write_jsonl(ROOT / args.output, decoded_rows)
    report["benchmark"] = args.benchmark.replace("\\", "/")
    report["predictions"] = args.predictions.replace("\\", "/")
    report["output"] = args.output.replace("\\", "/")
    write_json(ROOT / args.report_output, report)

    if args.evaluation_output:
        evaluation = evaluate_relational_predictions(
            join_predictions(benchmark_rows, decoded_rows),
            bootstrap_iterations=args.bootstrap_iterations,
            bootstrap_seed=args.bootstrap_seed,
        )
        evaluation["decoder_report"] = args.report_output.replace("\\", "/")
        evaluation["decoded_predictions"] = args.output.replace("\\", "/")
        write_json(ROOT / args.evaluation_output, evaluation)

    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
