from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.cross_model_replication import (  # noqa: E402
    build_replication_report,
    markdown_report,
    pending_model,
    summarize_replication_model,
)
from vrf.io_utils import read_jsonl, write_json  # noqa: E402


def add_model_args(parser: argparse.ArgumentParser, prefix: str) -> None:
    parser.add_argument(f"--{prefix}-benchmark")
    parser.add_argument(f"--{prefix}-predictions")
    parser.add_argument(f"--{prefix}-model-id")
    parser.add_argument(f"--{prefix}-tokenizer-id")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the PR #12 cross-model replication report."
    )
    add_model_args(parser, "decoder")
    add_model_args(parser, "generative")
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_cross_model_replication_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/CROSS_MODEL_REPLICATION.md",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    models = []
    if args.decoder_benchmark and args.decoder_predictions:
        models.append(
            summarize_replication_model(
                read_jsonl(ROOT / args.decoder_benchmark),
                read_jsonl(ROOT / args.decoder_predictions),
                model_key="non_qwen_decoder_classifier",
                model_type="decoder_sequence_classifier",
                model_id=args.decoder_model_id or "unknown_decoder",
                tokenizer_id=args.decoder_tokenizer_id,
                supports_abstention=False,
                bootstrap_iterations=args.bootstrap_iterations,
                bootstrap_seed=args.bootstrap_seed,
            )
        )
        models[-1]["interpretation"] = (
            "Non-Qwen decoder classifier measured under fixed VeriPatch-RR."
        )
    else:
        models.append(
            pending_model(
                model_key="non_qwen_decoder_classifier",
                model_type="decoder_sequence_classifier",
                interpretation=(
                    "Pending prediction artifact; this slot tests whether "
                    "endpoint sensitivity is Qwen-specific."
                ),
            )
        )

    if args.generative_benchmark and args.generative_predictions:
        models.append(
            summarize_replication_model(
                read_jsonl(ROOT / args.generative_benchmark),
                read_jsonl(ROOT / args.generative_predictions),
                model_key="generative_instruction_judge",
                model_type="generative_instruction_judge",
                model_id=args.generative_model_id or "unknown_generative",
                tokenizer_id=args.generative_tokenizer_id,
                supports_abstention=True,
                bootstrap_iterations=args.bootstrap_iterations,
                bootstrap_seed=args.bootstrap_seed + 17,
            )
        )
        models[-1]["interpretation"] = (
            "Generative judge measured with strict A/B/INSUFFICIENT_CONTEXT outputs."
        )
    else:
        models.append(
            pending_model(
                model_key="generative_instruction_judge",
                model_type="generative_instruction_judge",
                interpretation=(
                    "Pending prediction artifact; this slot tests whether "
                    "side-order failure appears without a classification head."
                ),
            )
        )

    report = build_replication_report(models)
    write_json(ROOT / args.json_output, report)
    (ROOT / args.markdown_output).write_text(
        markdown_report(report), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
