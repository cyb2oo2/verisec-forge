"""One preregistered repair run: antisymmetric-head fine-tune (docs/REPAIR_EXPERIMENT_PREREGISTRATION.md).

Trains the shared sequence encoder with an antisymmetric readout over the two
renderings of a pair: g(text) = logit_vuln - logit_safe, score s = g(vuln
rendering) - g(safe rendering), optimized with BCE toward "the vulnerable
rendering scores higher". At inference the pair decision is s(rendering) -
s(reverse rendering), so side-swap equivariance and polarity invariance are
architecturally exact and the empirical question is whether canonical accuracy
holds. This is a trained architecture, not a post-hoc projection of the frozen
model (that would be the excluded TTA/decoder null).

Deviation note vs #53: the codebase model is a per-rendering sequence classifier
(predict_veripatch_rr scores one text at a time), so "the shared encoder's
pooled feature for the two orderings" is realized as g over a rendering and its
reverse rather than a bespoke two-candidate cross-encoder. Same guarantee.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.joint_reasoning import reverse_side_choice_text
from vrf.training_common import optional_import_train_stack


def pair_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[int, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["pair_key"]), {})[int(row["label"])] = row
    return [
        {
            "pair_key": pair_key,
            "safe_text": sides[0]["text"],
            "vulnerable_text": sides[1]["text"],
            "pair_length": max(len(sides[0]["text"]), len(sides[1]["text"])),
        }
        for pair_key, sides in sorted(grouped.items())
        if set(sides) == {0, 1}
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Antisymmetric-head repair fine-tune.")
    parser.add_argument("--config", default="configs/research_primevul_joint_pairwise_repair_antisymmetric_v1.json")
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--smoke", action="store_true", help="tiny run to validate the pipeline")
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    seed = int(config["seed"])
    transformers.set_seed(seed)
    tokenizer = transformers.AutoTokenizer.from_pretrained(config["init_checkpoint"], local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        ROOT / config["init_checkpoint"], local_files_only=True, is_trainable=True
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.enable_input_require_grads()

    train_pairs = pair_records(read_jsonl(ROOT / config["train_dataset"]))
    limit = args.max_train_pairs or (16 if args.smoke else config.get("max_train_pairs"))
    if limit:
        train_pairs = sorted(train_pairs, key=lambda r: str(r["pair_key"]))[: int(limit)]
    train_pairs = sorted(train_pairs, key=lambda r: int(r["pair_length"]))
    rng = random.Random(seed)
    rng.shuffle(train_pairs)
    train_dataset = datasets.Dataset.from_list(train_pairs)
    max_length = int(config["max_seq_length"])
    collapse_weight = float(config["loss"].get("collapse_weight", 0.1))

    class Collator:
        def __call__(self, features: list[dict[str, Any]]) -> dict[str, Any]:
            texts = []
            for f in features:
                texts.extend([f["safe_text"], f["vulnerable_text"]])
            encoded = tokenizer(
                texts, truncation=True, max_length=max_length, padding=True,
                pad_to_multiple_of=8, return_tensors="pt",
            )
            encoded["n_pairs"] = torch.tensor(len(features))
            return encoded

    class RepairTrainer(transformers.Trainer):
        def _get_train_sampler(self, train_dataset=None):
            return torch.utils.data.SequentialSampler(train_dataset or self.train_dataset)

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            n = int(inputs.pop("n_pairs"))
            outputs = model(**inputs)
            logits = outputs.logits  # (2n, 2): rows are [safe, vuln] per pair
            g = (logits[:, 1] - logits[:, 0]).reshape(n, 2)  # [g_safe, g_vuln]
            score = g[:, 1] - g[:, 0]  # antisymmetric: vuln rendering minus safe
            # BCE toward "vulnerable rendering scores higher" (gold = 1).
            bce = torch.nn.functional.softplus(-score).mean()
            # Collapse guard: keep the score spread up (avoid saturating to a constant).
            probs = torch.sigmoid(score)
            variance_shortfall = torch.clamp(0.02 - probs.var(unbiased=False), min=0.0)
            loss = bce + collapse_weight * variance_shortfall
            return (loss, outputs) if return_outputs else loss

    training = config["training"]
    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    epochs = 1 if args.smoke else float(training["num_train_epochs"])
    steps = math.ceil(len(train_pairs) / (int(training["per_device_train_batch_size"]) * int(training["gradient_accumulation_steps"])))
    print(f"repair: train_pairs={len(train_pairs)} steps/epoch={steps} max_length={max_length} "
          f"smoke={args.smoke} device={torch.cuda.get_device_name(0)}", flush=True)

    trainer = RepairTrainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir=str(output_dir), num_train_epochs=epochs,
            learning_rate=float(training["learning_rate"]),
            per_device_train_batch_size=int(training["per_device_train_batch_size"]),
            gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
            logging_steps=int(training["logging_steps"]), save_strategy="no",
            fp16=False, bf16=True, gradient_checkpointing=True, report_to=[],
            seed=seed, data_seed=seed, remove_unused_columns=False,
            max_steps=3 if args.smoke else -1,
        ),
        train_dataset=train_dataset, data_collator=Collator(),
    )
    trainer.train()
    if not args.smoke:
        trainer.save_model(str(output_dir))
        tokenizer.save_pretrained(str(output_dir))
    write_json(ROOT / "reports" / f"repair_train_status_{'smoke' if args.smoke else 'v1'}.json",
               {"status": "ok", "train_pairs": len(train_pairs), "steps_per_epoch": steps,
                "smoke": args.smoke, "output_dir": config["output_dir"]})
    print("training complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
