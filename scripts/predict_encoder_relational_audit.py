from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from vrf.io_utils import read_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run encoder sequence-classifier relational inference."
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_joint_side_choice_codebert_v1",
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    rows = read_jsonl(args.dataset)
    tokenizer = AutoTokenizer.from_pretrained(
        args.checkpoint, local_files_only=True
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        args.checkpoint, local_files_only=True, dtype=torch.bfloat16
    ).to("cuda")
    model.eval()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with output_path.open("w", encoding="utf-8") as handle:
        for start in range(0, len(rows), args.batch_size):
            batch = rows[start : start + args.batch_size]
            encoded = tokenizer(
                [str(row["text"]) for row in batch],
                truncation=True,
                max_length=int(
                    batch[0]["runtime_accounting"]["max_length"]
                ),
                padding=True,
                pad_to_multiple_of=8,
                return_tensors="pt",
            ).to("cuda")
            with torch.inference_mode():
                probabilities = torch.softmax(
                    model(**encoded).logits.float(), dim=-1
                ).cpu()
            for row, probability in zip(batch, probabilities, strict=True):
                probability_b = float(probability[1])
                prediction = {
                    "id": row["id"],
                    "predicted_riskier_side": (
                        "B" if probability_b > 0.5 else "A"
                    ),
                    "probability_a": 1.0 - probability_b,
                    "probability_b": probability_b,
                    "confidence": max(probability_b, 1.0 - probability_b),
                    "model_id": args.checkpoint,
                    "supports_abstention": False,
                }
                handle.write(json.dumps(prediction) + "\n")
            if start == 0 or start + len(batch) == len(rows):
                print(f"progress {start + len(batch)}/{len(rows)}", flush=True)
    elapsed = time.perf_counter() - started
    print(
        json.dumps(
            {
                "status": "ok",
                "rows": len(rows),
                "seconds": round(elapsed, 2),
                "rows_per_second": round(len(rows) / elapsed, 3),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
