from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.decoder_stress_validation import run_decoder_stress_validation
from vrf.io_utils import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run relation-consistent decoder stress validation."
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--randomized-seed", type=int, default=42)
    args = parser.parse_args()

    report = run_decoder_stress_validation(
        read_jsonl(ROOT / args.benchmark),
        read_jsonl(ROOT / args.predictions),
        bootstrap_iterations=args.bootstrap_iterations,
        randomized_seed=args.randomized_seed,
    )
    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": report["status"], "output": args.output}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
