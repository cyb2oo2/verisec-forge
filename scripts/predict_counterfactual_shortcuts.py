from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl


def _softmax_positive(torch: Any, logits: Any) -> list[float]:
    return torch.softmax(logits.float(), dim=-1)[:, 1].detach().cpu().tolist()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run batched GPU inference over counterfactual shortcut interventions.")
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1",
    )
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_primevul_counterfactual_interventions_v1.jsonl",
    )
    parser.add_argument(
        "--base-predictions",
        default="outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--output",
        default="outputs/secure_code_primevul_counterfactual_intervention_predictions_v1.jsonl",
    )
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--progress-every", type=int, default=10)
    args = parser.parse_args()

    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the counterfactual benchmark run")

    rows = read_jsonl(args.dataset)
    if args.limit:
        rows = rows[: args.limit]
    base_predictions = {str(row["id"]): row for row in read_jsonl(args.base_predictions)}

    tokenizer = AutoTokenizer.from_pretrained(args.checkpoint, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(args.checkpoint, local_files_only=True)
    model.config.pad_token_id = tokenizer.pad_token_id
    device = torch.device("cuda")
    model.to(device)
    model.eval()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    processed = 0
    with output_path.open("w", encoding="utf-8") as handle:
        for batch_index, start in enumerate(range(0, len(rows), args.batch_size), start=1):
            batch_rows = rows[start : start + args.batch_size]
            tokenized = tokenizer(
                [str(row["text"]) for row in batch_rows],
                truncation=True,
                max_length=args.max_seq_length,
                padding=True,
                return_tensors="pt",
            )
            tokenized = {key: value.to(device, non_blocking=True) for key, value in tokenized.items()}
            with torch.inference_mode():
                probabilities = _softmax_positive(torch, model(**tokenized).logits)
            for row, probability in zip(batch_rows, probabilities, strict=True):
                base = base_predictions.get(str(row["base_id"]), {})
                base_probability = float(base.get("vuln_probability") or 0.0)
                output_row = {
                    "id": row["id"],
                    "base_id": row["base_id"],
                    "pair_key": row.get("pair_key"),
                    "intervention": row["intervention"],
                    "expected_relation": row["expected_relation"],
                    "base_label": row.get("base_label"),
                    "expected_label": row.get("expected_label"),
                    "base_pred": int(base.get("pre_coupled_pred", base.get("pred", base_probability >= args.threshold))),
                    "base_confidence": max(base_probability, 1.0 - base_probability),
                    "intervention_pred": int(probability >= args.threshold),
                    "intervention_probability": float(probability),
                    "intervention_confidence": max(float(probability), 1.0 - float(probability)),
                    "intervention_abstain": False,
                }
                handle.write(json.dumps(output_row, ensure_ascii=False) + "\n")
            processed += len(batch_rows)
            if batch_index == 1 or batch_index % args.progress_every == 0 or processed == len(rows):
                elapsed = max(time.perf_counter() - started, 1e-9)
                rate = processed / elapsed
                eta = (len(rows) - processed) / rate if rate else 0.0
                allocated_gib = torch.cuda.memory_allocated() / (1024**3)
                print(
                    f"progress {processed}/{len(rows)} "
                    f"({processed / len(rows):.1%}) rate={rate:.2f} rows/s "
                    f"eta={eta / 60:.1f}m gpu_alloc={allocated_gib:.2f}GiB",
                    flush=True,
                )

    elapsed = time.perf_counter() - started
    print(
        json.dumps(
            {
                "status": "ok",
                "rows": processed,
                "seconds": round(elapsed, 2),
                "rows_per_second": round(processed / elapsed, 3) if elapsed else None,
                "output": args.output,
                "batch_size": args.batch_size,
                "max_seq_length": args.max_seq_length,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
