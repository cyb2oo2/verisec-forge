from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl


def prediction_from_probability(
    row_id: str,
    probability_b: float,
    *,
    model_id: str,
) -> dict[str, Any]:
    probability_a = 1.0 - probability_b
    predicted_side = "A" if probability_a >= probability_b else "B"
    return {
        "id": row_id,
        "predicted_riskier_side": predicted_side,
        "probability_a": probability_a,
        "probability_b": probability_b,
        "confidence": max(probability_a, probability_b),
        "model_id": model_id,
        "supports_abstention": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run serial batched GPU inference over VeriPatch-RR."
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1",
    )
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_relational_benchmark_v2_qwen15b_runtime.jsonl",
    )
    parser.add_argument(
        "--output",
        default="outputs/secure_code_veripatch_rr_qwen15b_smoke_predictions.jsonl",
    )
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--progress-every", type=int, default=25)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for VeriPatch-RR inference")

    rows = read_jsonl(args.dataset)
    if args.limit:
        rows = rows[: args.limit]
    invalid_accounting = [
        row["id"]
        for row in rows
        if row["runtime_accounting"].get("offset_mapping_quality")
        != "exact_fast_tokenizer"
    ]
    if invalid_accounting:
        raise ValueError(
            "VeriPatch-RR inference requires exact runtime accounting; "
            f"first={invalid_accounting[0]}"
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed_ids = set()
    mode = "w"
    if args.resume and output_path.exists():
        completed_ids = {
            str(row["id"]) for row in read_jsonl(output_path)
        }
        mode = "a"
    pending = [
        row for row in rows if str(row["id"]) not in completed_ids
    ]
    pending.sort(
        key=lambda row: (
            int(row["runtime_accounting"]["token_count"]),
            str(row["id"]),
        )
    )

    tokenizer = AutoTokenizer.from_pretrained(
        args.checkpoint, local_files_only=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        args.checkpoint,
        local_files_only=True,
        dtype=torch.bfloat16,
        is_trainable=False,
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.to(torch.device("cuda"))
    model.eval()

    total = len(rows)
    processed = len(completed_ids)
    started = time.perf_counter()
    print(
        f"VeriPatch-RR inference: total={total} pending={len(pending)} "
        f"batch_size={args.batch_size} device={torch.cuda.get_device_name(0)}",
        flush=True,
    )
    with output_path.open(mode, encoding="utf-8") as handle:
        for batch_index, start in enumerate(
            range(0, len(pending), args.batch_size), start=1
        ):
            batch = pending[start : start + args.batch_size]
            tokenized = tokenizer(
                [str(row["text"]) for row in batch],
                truncation=True,
                max_length=int(
                    batch[0]["runtime_accounting"]["max_length"]
                ),
                padding=True,
                pad_to_multiple_of=8,
                return_tensors="pt",
            )
            tokenized = {
                key: value.to("cuda", non_blocking=True)
                for key, value in tokenized.items()
            }
            with torch.inference_mode():
                logits = model(**tokenized).logits
                probabilities_b = (
                    torch.softmax(logits.float(), dim=-1)[:, 1]
                    .detach()
                    .cpu()
                    .tolist()
                )
            for row, probability_b in zip(
                batch, probabilities_b, strict=True
            ):
                prediction = prediction_from_probability(
                    str(row["id"]),
                    float(probability_b),
                    model_id=args.checkpoint,
                )
                handle.write(
                    json.dumps(prediction, ensure_ascii=False) + "\n"
                )
            handle.flush()
            processed += len(batch)
            if (
                batch_index == 1
                or batch_index % args.progress_every == 0
                or processed == total
            ):
                elapsed = max(time.perf_counter() - started, 1e-9)
                newly_processed = processed - len(completed_ids)
                rate = newly_processed / elapsed
                eta = (total - processed) / rate if rate else 0.0
                print(
                    f"progress {processed}/{total} ({processed / total:.1%}) "
                    f"rate={rate:.2f} rows/s eta={eta / 60:.1f}m "
                    f"gpu_alloc={torch.cuda.memory_allocated() / 1024**3:.2f}GiB "
                    f"gpu_reserved={torch.cuda.memory_reserved() / 1024**3:.2f}GiB",
                    flush=True,
                )

    elapsed = time.perf_counter() - started
    print(
        json.dumps(
            {
                "status": "ok",
                "rows": total,
                "new_rows": len(pending),
                "seconds": round(elapsed, 2),
                "rows_per_second": (
                    round(len(pending) / elapsed, 3) if elapsed else None
                ),
                "output": str(output_path),
            },
            indent=2,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
