from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a non-Qwen decoder classifier through VeriPatch-RR."
    )
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument(
        "--runtime",
        required=True,
        help="Runtime-materialized VeriPatch-RR JSONL for this tokenizer.",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    checkpoint_name = args.checkpoint.lower()
    if "qwen" in checkpoint_name:
        raise ValueError(
            "PR #12A requires a non-Qwen decoder classifier checkpoint."
        )

    command = [
        sys.executable,
        str(ROOT / "scripts" / "predict_veripatch_rr.py"),
        "--checkpoint",
        args.checkpoint,
        "--dataset",
        args.runtime,
        "--output",
        args.output,
        "--batch-size",
        str(args.batch_size),
    ]
    if args.limit is not None:
        command.extend(["--limit", str(args.limit)])
    if args.resume:
        command.append("--resume")
    return subprocess.call(command, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
