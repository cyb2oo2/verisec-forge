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
from vrf.readout_classifier import (
    READOUT_TYPES,
    build_readout_classifier,
    tokenize_readout_batch,
)
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
            "pair_length": max(
                len(sides[0]["text"]),
                len(sides[1]["text"]),
            ),
        }
        for pair_key, sides in sorted(grouped.items())
        if set(sides) == {0, 1}
    ]


def length_bucket_order(
    rows: list[dict[str, Any]],
    *,
    seed: int,
    bucket_size: int = 32,
) -> list[dict[str, Any]]:
    ordered = sorted(rows, key=lambda row: int(row["pair_length"]))
    buckets = [
        ordered[start : start + bucket_size]
        for start in range(0, len(ordered), bucket_size)
    ]
    rng = random.Random(seed)
    for bucket in buckets:
        rng.shuffle(bucket)
    rng.shuffle(buckets)
    return [row for bucket in buckets for row in bucket]


def pair_metrics(
    predictions: list[dict[str, Any]],
) -> dict[str, float | int]:
    grouped: dict[str, dict[int, float]] = {}
    for row in predictions:
        grouped.setdefault(str(row["pair_key"]), {})[
            int(row["gold"])
        ] = float(row["side_b_vulnerable_probability"])
    complete = [scores for scores in grouped.values() if set(scores) == {0, 1}]
    return {
        "unique_pairs": len(complete),
        "pair_orientation_accuracy": (
            sum(scores[1] > scores[0] for scores in complete) / len(complete)
            if complete
            else 0.0
        ),
        "independent_both_correct": (
            sum(scores[0] < 0.5 <= scores[1] for scores in complete)
            / len(complete)
            if complete
            else 0.0
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train a same-backbone secure-patch readout ablation."
    )
    parser.add_argument(
        "--config",
        default="configs/research_primevul_readout_ablation_qwen15b_v1.json",
    )
    parser.add_argument("--readout", choices=READOUT_TYPES, required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--run-tag", default="")
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--max-eval-examples", type=int)
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    seed = int(args.seed if args.seed is not None else config["seed"])
    transformers.set_seed(seed)
    init_checkpoint = ROOT / config["init_checkpoint"]
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        init_checkpoint,
        local_files_only=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    peft_model = AutoPeftModelForSequenceClassification.from_pretrained(
        init_checkpoint,
        local_files_only=True,
        is_trainable=True,
    )
    peft_model.config.pad_token_id = tokenizer.pad_token_id
    model = build_readout_classifier(
        peft_model,
        readout_type=args.readout,
    )
    model.enable_input_require_grads()

    train_pairs = pair_records(read_jsonl(ROOT / config["train_dataset"]))
    if args.max_train_pairs:
        train_pairs = train_pairs[: args.max_train_pairs]
    train_pairs = length_bucket_order(train_pairs, seed=seed)
    eval_rows = read_jsonl(ROOT / config["eval_dataset"])
    if args.max_eval_examples:
        eval_rows = eval_rows[: args.max_eval_examples]
    train_dataset = datasets.Dataset.from_list(train_pairs)
    max_length = int(config["max_seq_length"])

    class PairCollator:
        def __call__(
            self,
            features: list[dict[str, Any]],
        ) -> dict[str, Any]:
            texts = []
            for feature in features:
                texts.extend(
                    [feature["safe_text"], feature["vulnerable_text"]]
                )
            encoded = tokenize_readout_batch(
                tokenizer,
                texts,
                readout_type=args.readout,
                max_length=max_length,
            )
            encoded["pair_labels"] = torch.tensor(
                [[0, 1]] * len(features),
                dtype=torch.long,
            )
            return encoded

    class PairwiseTrainer(transformers.Trainer):
        def _get_train_sampler(self, train_dataset=None):
            return torch.utils.data.SequentialSampler(
                train_dataset or self.train_dataset
            )

        def compute_loss(
            self,
            model: Any,
            inputs: dict[str, Any],
            return_outputs: bool = False,
            **_: Any,
        ) -> Any:
            labels = inputs.pop("pair_labels")
            outputs = model(**inputs)
            logits = outputs.logits.reshape(labels.shape[0], 2, 2)
            classification = torch.nn.functional.cross_entropy(
                logits.reshape(-1, 2),
                labels.reshape(-1),
            )
            vulnerable_scores = logits[:, :, 1]
            margin = torch.relu(
                float(config["loss"]["margin"])
                - (vulnerable_scores[:, 1] - vulnerable_scores[:, 0])
            ).mean()
            probabilities = logits.softmax(dim=-1)[:, :, 1]
            complement = ((probabilities.sum(dim=1) - 1.0) ** 2).mean()
            loss = (
                classification
                + float(config["loss"]["margin_weight"]) * margin
                + float(config["loss"]["complement_weight"]) * complement
            )
            return (loss, outputs) if return_outputs else loss

    format_values = {
        "readout": args.readout,
        "seed": seed,
        "run_tag": args.run_tag,
    }
    run_name = config["name_template"].format(**format_values)
    output_dir = ROOT / config["output_dir_template"].format(
        **format_values
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    training = config["training"]
    effective_batch = int(training["per_device_train_batch_size"]) * int(
        training["gradient_accumulation_steps"]
    )
    steps = math.ceil(len(train_pairs) / effective_batch)
    print(
        f"{run_name}: readout={args.readout} train_pairs={len(train_pairs)} "
        f"steps/epoch={steps} max_length={max_length} "
        f"device={torch.cuda.get_device_name(0)}",
        flush=True,
    )
    trainer = PairwiseTrainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=float(training["num_train_epochs"]),
            learning_rate=float(training["learning_rate"]),
            per_device_train_batch_size=int(
                training["per_device_train_batch_size"]
            ),
            gradient_accumulation_steps=int(
                training["gradient_accumulation_steps"]
            ),
            logging_steps=int(training["logging_steps"]),
            save_strategy="no",
            fp16=False,
            bf16=True,
            gradient_checkpointing=True,
            report_to=[],
            seed=seed,
            data_seed=seed,
            remove_unused_columns=False,
        ),
        train_dataset=train_dataset,
        data_collator=PairCollator(),
    )
    trainer.train()
    peft_model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    write_json(
        output_dir / "readout_config.json",
        {
            "readout_type": args.readout,
            "init_checkpoint": config["init_checkpoint"],
            "max_seq_length": max_length,
        },
    )

    probabilities = []
    model.eval()
    batch_size = int(training["per_device_eval_batch_size"])
    for start in range(0, len(eval_rows), batch_size):
        batch = eval_rows[start : start + batch_size]
        inputs = tokenize_readout_batch(
            tokenizer,
            [str(row["text"]) for row in batch],
            readout_type=args.readout,
            max_length=max_length,
        )
        inputs = {
            key: value.to("cuda", non_blocking=True)
            for key, value in inputs.items()
        }
        with torch.inference_mode():
            logits = model(**inputs).logits
            probabilities.extend(
                torch.softmax(logits.float(), dim=-1)[:, 1]
                .cpu()
                .tolist()
            )
    predictions = []
    for row, probability in zip(eval_rows, probabilities, strict=True):
        predictions.append(
            {
                "id": row["id"],
                "pair_key": row["pair_key"],
                "gold": int(row["label"]),
                "pred": int(probability >= 0.5),
                "side_b_vulnerable_probability": float(probability),
            }
        )
    accuracy = float(
        np.mean([row["gold"] == row["pred"] for row in predictions])
    )
    report = {
        "status": "ok",
        "name": run_name,
        "readout_type": args.readout,
        "seed": seed,
        "train_pairs": len(train_pairs),
        "eval_examples": len(eval_rows),
        "canonical_accuracy": accuracy,
        "pair_metrics": pair_metrics(predictions),
        "training_contract": {
            "init_checkpoint": config["init_checkpoint"],
            "loss": config["loss"],
            "max_seq_length": max_length,
            "training": training,
        },
    }
    write_json(
        ROOT / config["report_output_template"].format(
            **format_values
        ),
        report,
    )
    predictions_path = ROOT / config["predictions_output_template"].format(
        **format_values
    )
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
