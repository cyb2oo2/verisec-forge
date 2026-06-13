from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl
from vrf.readout_classifier import (
    READOUT_TYPES,
    build_readout_classifier,
    tokenize_readout_batch,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a trained readout ablation over fixed audit rows."
    )
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--readout", choices=READOUT_TYPES, required=True)
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime512.jsonl",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--progress-every", type=int, default=25)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    rows = read_jsonl(ROOT / args.dataset)
    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = set()
    mode = "w"
    if args.resume and output_path.exists():
        completed = {str(row["id"]) for row in read_jsonl(output_path)}
        mode = "a"
    pending = [row for row in rows if str(row["id"]) not in completed]
    pending.sort(
        key=lambda row: (
            int(row["runtime_accounting"]["token_count"]),
            str(row["id"]),
        )
    )

    checkpoint = ROOT / args.checkpoint
    tokenizer = AutoTokenizer.from_pretrained(
        checkpoint,
        local_files_only=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    peft_model = AutoPeftModelForSequenceClassification.from_pretrained(
        checkpoint,
        local_files_only=True,
        dtype=torch.bfloat16,
        is_trainable=False,
    )
    peft_model.config.pad_token_id = tokenizer.pad_token_id
    model = build_readout_classifier(
        peft_model,
        readout_type=args.readout,
    )
    model.to("cuda")
    model.eval()

    started = time.perf_counter()
    processed = len(completed)
    with output_path.open(mode, encoding="utf-8") as handle:
        for batch_index, start in enumerate(
            range(0, len(pending), args.batch_size),
            start=1,
        ):
            batch = pending[start : start + args.batch_size]
            inputs = tokenize_readout_batch(
                tokenizer,
                [str(row["text"]) for row in batch],
                readout_type=args.readout,
                max_length=args.max_length,
            )
            inputs = {
                key: value.to("cuda", non_blocking=True)
                for key, value in inputs.items()
            }
            with torch.inference_mode():
                logits = model(**inputs).logits
                probabilities = torch.softmax(
                    logits.float(),
                    dim=-1,
                ).cpu()
            for row, probs in zip(batch, probabilities, strict=True):
                probability_a = float(probs[0])
                probability_b = float(probs[1])
                handle.write(
                    json.dumps(
                        {
                            "id": row["id"],
                            "predicted_riskier_side": (
                                "A"
                                if probability_a >= probability_b
                                else "B"
                            ),
                            "probability_a": probability_a,
                            "probability_b": probability_b,
                            "confidence": max(
                                probability_a,
                                probability_b,
                            ),
                            "model_id": args.checkpoint,
                            "readout_type": args.readout,
                            "supports_abstention": False,
                        }
                    )
                    + "\n"
                )
            handle.flush()
            processed += len(batch)
            if (
                batch_index == 1
                or batch_index % args.progress_every == 0
                or processed == len(rows)
            ):
                elapsed = max(time.perf_counter() - started, 1e-9)
                rate = (processed - len(completed)) / elapsed
                eta = (len(rows) - processed) / rate if rate else 0.0
                print(
                    f"{args.readout}: {processed}/{len(rows)} "
                    f"({processed / len(rows):.1%}) "
                    f"rate={rate:.2f} rows/s eta={eta / 60:.1f}m",
                    flush=True,
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
