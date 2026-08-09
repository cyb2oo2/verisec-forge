"""Polarity-adversarial training (Option A: gradient reversal).

Extends the antisymmetric repair objective with an auxiliary head that predicts
the sign of the pair's net character change from the *same* pooled representation
used for the relational decision. The representation passes through a gradient
reversal layer before the auxiliary head, so:

* the auxiliary head learns to read polarity as well as it can, while
* the encoder is pushed to make polarity **unreadable** from its features.

    total = L_main + aux_weight * L_polarity      (GRL scales encoder grads by -lambda)

The point is that ``reports/PROSE_NATIVE_PILOT_V1.md`` showed removing the glyph
*encoding* does not remove the polarity *shortcut* -- the model simply relearned
net polarity from the prose block sizes. A rendering-level fix cannot work, so
this attacks the statistic directly.

Polarity labels come from the pair's glyph rendering (``polarity_sign`` in the
training data), because the prose rendering carries no +/- lines. Rows with zero
net change are masked out of the auxiliary loss.

Logged per interval: main loss, auxiliary loss, auxiliary polarity accuracy
(the diagnostic that says whether the adversary is actually working -- it should
fall toward chance as the encoder sheds polarity information).
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import read_jsonl, write_json
from vrf.training_common import optional_import_train_stack


def pair_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[int, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["pair_key"]), {})[int(row["label"])] = row
    records = []
    for pair_key, sides in sorted(grouped.items()):
        if set(sides) != {0, 1}:
            continue
        records.append(
            {
                "pair_key": pair_key,
                "safe_text": sides[0]["text"],
                "vulnerable_text": sides[1]["text"],
                # polarity sign of each rendering, in the same [safe, vuln] order
                "safe_polarity": int(sides[0].get("polarity_sign", 0)),
                "vulnerable_polarity": int(sides[1].get("polarity_sign", 0)),
                "pair_length": max(len(sides[0]["text"]), len(sides[1]["text"])),
            }
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Polarity-adversarial fine-tune (GRL).")
    parser.add_argument("--config", default="configs/research_polarity_adversarial_v1.json")
    parser.add_argument("--lambda-grl", type=float)
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    seed = int(config["seed"])
    transformers.set_seed(seed)
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        config["init_checkpoint"], local_files_only=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        ROOT / config["init_checkpoint"], local_files_only=True, is_trainable=True
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.enable_input_require_grads()

    adversary = config.get("adversary", {})
    lambda_grl = float(
        args.lambda_grl if args.lambda_grl is not None else adversary.get("lambda_grl", 0.1)
    )
    aux_weight = float(adversary.get("aux_weight", 1.0))
    aux_hidden = int(adversary.get("aux_hidden", 128))

    class GradientReversal(torch.autograd.Function):
        @staticmethod
        def forward(ctx, x, lambd):
            ctx.lambd = lambd
            return x.view_as(x)

        @staticmethod
        def backward(ctx, grad_output):
            return -ctx.lambd * grad_output, None

    hidden_size = int(model.config.hidden_size)
    aux_head = torch.nn.Sequential(
        torch.nn.Linear(hidden_size, aux_hidden),
        torch.nn.Tanh(),
        torch.nn.Linear(aux_hidden, 1),
    )
    aux_head.to(device=model.device, dtype=torch.float32)
    for param in aux_head.parameters():
        param.requires_grad_(True)
    # Register on the PEFT model so Trainer's optimizer picks the params up.
    # PEFT's save_pretrained writes adapter weights only, so the auxiliary head
    # is intentionally not persisted -- it exists to shape the encoder, not for
    # inference.
    model.polarity_adversary = aux_head

    train_rows = read_jsonl(ROOT / config["train_dataset"])
    train_pairs = pair_records(train_rows)
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
            texts, polarity = [], []
            for f in features:
                texts.extend([f["safe_text"], f["vulnerable_text"]])
                polarity.extend([f["safe_polarity"], f["vulnerable_polarity"]])
            encoded = tokenizer(
                texts,
                truncation=True,
                max_length=max_length,
                padding=True,
                pad_to_multiple_of=8,
                return_tensors="pt",
            )
            encoded["n_pairs"] = torch.tensor(len(features))
            encoded["polarity"] = torch.tensor(polarity, dtype=torch.float32)
            return encoded

    class AdversarialTrainer(transformers.Trainer):
        def __init__(self, *a: Any, **kw: Any) -> None:
            super().__init__(*a, **kw)
            self.aux_hits = 0.0
            self.aux_total = 0.0
            self.aux_loss_sum = 0.0
            self.main_loss_sum = 0.0
            self.observations = 0

        def _get_train_sampler(self, train_dataset=None):
            return torch.utils.data.SequentialSampler(train_dataset or self.train_dataset)

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            n = int(inputs.pop("n_pairs"))
            polarity = inputs.pop("polarity")
            attention_mask = inputs["attention_mask"]
            outputs = model(**inputs, output_hidden_states=True)

            logits = outputs.logits  # (2n, 2): rows are [safe, vuln] per pair
            g = (logits[:, 1] - logits[:, 0]).reshape(n, 2)
            score = g[:, 1] - g[:, 0]
            bce = torch.nn.functional.softplus(-score).mean()
            probs = torch.sigmoid(score)
            variance_shortfall = torch.clamp(0.02 - probs.var(unbiased=False), min=0.0)
            main_loss = bce + collapse_weight * variance_shortfall

            # Pool the last non-pad position: the same readout the classifier uses.
            last_hidden = outputs.hidden_states[-1]
            lengths = attention_mask.sum(dim=1) - 1
            pooled = last_hidden[torch.arange(last_hidden.size(0)), lengths]

            reversed_features = GradientReversal.apply(pooled.float(), lambda_grl)
            aux_logits = model.polarity_adversary(reversed_features).squeeze(-1)

            mask = polarity.to(aux_logits.device) != 0
            if mask.any():
                targets = (polarity.to(aux_logits.device)[mask] > 0).float()
                aux_loss = torch.nn.functional.binary_cross_entropy_with_logits(
                    aux_logits[mask], targets
                )
                with torch.no_grad():
                    predicted = (aux_logits[mask] > 0).float()
                    self.aux_hits += float((predicted == targets).sum())
                    self.aux_total += float(mask.sum())
            else:
                aux_loss = aux_logits.sum() * 0.0

            loss = main_loss + aux_weight * aux_loss
            with torch.no_grad():
                self.main_loss_sum += float(main_loss)
                self.aux_loss_sum += float(aux_loss)
                self.observations += 1
            return (loss, outputs) if return_outputs else loss

        def log(self, logs: dict[str, float], *a: Any, **kw: Any) -> None:
            if self.observations:
                logs["main_loss"] = round(self.main_loss_sum / self.observations, 4)
                logs["aux_polarity_loss"] = round(self.aux_loss_sum / self.observations, 4)
                logs["aux_polarity_accuracy"] = (
                    round(self.aux_hits / self.aux_total, 4) if self.aux_total else None
                )
                logs["lambda_grl"] = lambda_grl
                self.aux_hits = self.aux_total = 0.0
                self.aux_loss_sum = self.main_loss_sum = 0.0
                self.observations = 0
            super().log(logs, *a, **kw)

    training = config["training"]
    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    epochs = 1 if args.smoke else float(training["num_train_epochs"])
    steps = math.ceil(
        len(train_pairs)
        / (
            int(training["per_device_train_batch_size"])
            * int(training["gradient_accumulation_steps"])
        )
    )
    print(
        f"polarity-adversarial: pairs={len(train_pairs)} steps/epoch={steps} "
        f"lambda_grl={lambda_grl} aux_weight={aux_weight} max_length={max_length} "
        f"smoke={args.smoke} device={torch.cuda.get_device_name(0)}",
        flush=True,
    )

    trainer = AdversarialTrainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=epochs,
            learning_rate=float(training["learning_rate"]),
            per_device_train_batch_size=int(training["per_device_train_batch_size"]),
            gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
            logging_steps=int(training["logging_steps"]),
            save_strategy="no",
            fp16=False,
            bf16=True,
            gradient_checkpointing=True,
            report_to=[],
            seed=seed,
            data_seed=seed,
            remove_unused_columns=False,
            max_steps=3 if args.smoke else -1,
        ),
        train_dataset=train_dataset,
        data_collator=Collator(),
    )
    trainer.train()
    if not args.smoke:
        trainer.save_model(str(output_dir))
        tokenizer.save_pretrained(str(output_dir))

    history = [h for h in trainer.state.log_history if "aux_polarity_accuracy" in h]
    write_json(
        ROOT / "reports" / f"polarity_adversarial_train_status_{'smoke' if args.smoke else 'v1'}.json",
        {
            "status": "ok",
            "config": args.config,
            "train_pairs": len(train_pairs),
            "steps_per_epoch": steps,
            "lambda_grl": lambda_grl,
            "aux_weight": aux_weight,
            "aux_hidden": aux_hidden,
            "smoke": args.smoke,
            "output_dir": config["output_dir"],
            "log_history": history,
        },
    )
    print("training complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
