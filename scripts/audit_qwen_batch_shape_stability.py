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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay one Qwen boundary sample under fixed padding shapes."
    )
    parser.add_argument(
        "--runtime",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime512.jsonl",
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1",
    )
    parser.add_argument("--pair-key", default="patcheval-681-0")
    parser.add_argument(
        "--output",
        default="reports/secure_code_qwen_batch_shape_stability_v1.json",
    )
    args = parser.parse_args()

    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    target = next(
        row
        for row in read_jsonl(ROOT / args.runtime)
        if row["pair_key"] == args.pair_key
        and row["audit_variant"] == "canonical"
    )
    tokenizer = AutoTokenizer.from_pretrained(
        ROOT / args.checkpoint, local_files_only=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        ROOT / args.checkpoint,
        local_files_only=True,
        dtype=torch.bfloat16,
        is_trainable=False,
    ).to("cuda")
    model.config.pad_token_id = tokenizer.pad_token_id
    model.eval()

    results = []
    for batch_size in (1, 8):
        for padded_length in (224, 232, 512):
            encoded = tokenizer(
                [target["text"]] * batch_size,
                truncation=True,
                max_length=512,
                padding="max_length",
                return_tensors="pt",
            )
            encoded = {
                key: value[:, :padded_length].to("cuda")
                for key, value in encoded.items()
            }
            with torch.inference_mode():
                probabilities = torch.softmax(
                    model(**encoded).logits.float(), dim=-1
                )[:, 1]
            probability_b = float(probabilities[0].cpu())
            results.append(
                {
                    "batch_size": batch_size,
                    "padded_length": padded_length,
                    "probability_a": 1.0 - probability_b,
                    "probability_b": probability_b,
                    "predicted_side": "B" if probability_b > 0.5 else "A",
                    "replicate_probability_range": (
                        float(
                            probabilities.max().cpu()
                            - probabilities.min().cpu()
                        )
                    ),
                }
            )

    payload = {
        "status": "ok",
        "pair_key": args.pair_key,
        "token_count": target["runtime_accounting"]["token_count"],
        "text_sha256": __import__("hashlib")
        .sha256(target["text"].encode("utf-8"))
        .hexdigest(),
        "results": results,
        "claim_boundary": (
            "This isolates padded tensor shape with identical target text and "
            "replicated batch content. A threshold crossing demonstrates "
            "numerical/readout sensitivity for one low-margin BF16 sample, "
            "not widespread prediction instability."
        ),
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
