from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.training_common import optional_import_train_stack, resolve_local_model_source


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    correct = sum(row["gold"] == row["pred"] for row in rows)
    pair_groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        pair_groups.setdefault(str(row["pair_key"]), []).append(row)
    all_correct = sum(all(row["gold"] == row["pred"] for row in group) for group in pair_groups.values())
    equivariant = sum(
        len(group) == 2 and {row["pred"] for row in group} == {0, 1}
        for group in pair_groups.values()
    )
    return {
        "examples": total,
        "unique_pairs": len(pair_groups),
        "side_choice_accuracy": correct / total if total else 0.0,
        "group_all_correct": all_correct / len(pair_groups) if pair_groups else 0.0,
        "side_swap_equivariance": equivariant / len(pair_groups) if pair_groups else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the first learned joint side-choice baseline.")
    parser.add_argument("--config", default="configs/research_primevul_joint_side_choice_qwen15b_v1.json")
    parser.add_argument("--max-train-examples", type=int)
    parser.add_argument("--max-eval-examples", type=int)
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification, LoraConfig, TaskType, get_peft_model

    seed = int(config["seed"])
    transformers.set_seed(seed)
    model_source = resolve_local_model_source(config["model_name"], True)
    tokenizer = transformers.AutoTokenizer.from_pretrained(model_source, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    init_checkpoint = config.get("init_checkpoint")
    if init_checkpoint:
        model = AutoPeftModelForSequenceClassification.from_pretrained(
            ROOT / init_checkpoint,
            local_files_only=True,
            is_trainable=True,
        )
    else:
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            model_source,
            num_labels=2,
            local_files_only=True,
        )
        peft = config["peft"]
        model = get_peft_model(
            model,
            LoraConfig(
                r=peft["r"],
                lora_alpha=peft["lora_alpha"],
                lora_dropout=peft["lora_dropout"],
                target_modules=peft["target_modules"],
                modules_to_save=["score"],
                bias="none",
                task_type=TaskType.SEQ_CLS,
            ),
        )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.enable_input_require_grads()

    train_rows = read_jsonl(ROOT / config["train_dataset"])
    eval_rows = read_jsonl(ROOT / config["eval_dataset"])
    if args.max_train_examples:
        train_rows = train_rows[: args.max_train_examples]
    if args.max_eval_examples:
        eval_rows = eval_rows[: args.max_eval_examples]

    def tokenize(batch: dict[str, list[Any]]) -> dict[str, Any]:
        encoded = tokenizer(
            batch["text"],
            truncation=True,
            max_length=int(config["max_seq_length"]),
            padding=False,
        )
        encoded["labels"] = batch["label"]
        return encoded

    train_dataset = datasets.Dataset.from_list(train_rows)
    eval_dataset = datasets.Dataset.from_list(eval_rows)
    keep_columns = {"input_ids", "attention_mask", "labels"}
    train_dataset = train_dataset.map(tokenize, batched=True, remove_columns=train_dataset.column_names)
    eval_dataset = eval_dataset.map(tokenize, batched=True, remove_columns=eval_dataset.column_names)
    train_dataset.set_format(type="torch", columns=[col for col in train_dataset.column_names if col in keep_columns])
    eval_dataset.set_format(type="torch", columns=[col for col in eval_dataset.column_names if col in keep_columns])

    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    training = config["training"]
    steps_per_epoch = math.ceil(
        len(train_rows)
        / (int(training["per_device_train_batch_size"]) * int(training["gradient_accumulation_steps"]))
    )
    print(
        f"joint baseline: train={len(train_rows)} eval={len(eval_rows)} "
        f"steps/epoch={steps_per_epoch} max_length={config['max_seq_length']} device={torch.cuda.get_device_name(0)}",
        flush=True,
    )
    training_args = transformers.TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=float(training["num_train_epochs"]),
        learning_rate=float(training["learning_rate"]),
        per_device_train_batch_size=int(training["per_device_train_batch_size"]),
        per_device_eval_batch_size=int(training["per_device_eval_batch_size"]),
        gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
        logging_steps=int(training["logging_steps"]),
        save_strategy="no",
        eval_strategy="no",
        fp16=False,
        bf16=True,
        gradient_checkpointing=True,
        report_to=[],
        seed=seed,
        data_seed=seed,
        remove_unused_columns=True,
    )
    trainer = transformers.Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=transformers.DataCollatorWithPadding(tokenizer=tokenizer, pad_to_multiple_of=8),
    )
    trainer.train()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    raw = trainer.predict(eval_dataset)
    logits = np.asarray(raw.predictions)
    shifted = logits - logits.max(axis=-1, keepdims=True)
    probabilities = np.exp(shifted) / np.exp(shifted).sum(axis=-1, keepdims=True)
    predictions = []
    for row, probs in zip(eval_rows, probabilities, strict=True):
        predictions.append(
            {
                "id": row["id"],
                "pair_key": row["pair_key"],
                "gold": int(row["label"]),
                "pred": int(probs.argmax()),
                "side_b_vulnerable_probability": float(probs[1]),
            }
        )
    report = {
        "status": "ok",
        "model": config["model_name"],
        "checkpoint": config["output_dir"],
        "init_checkpoint": init_checkpoint,
        "seed": seed,
        "metrics": compute_metrics(predictions),
        "claim_boundary": "First side-choice-only joint baseline; evidence and abstention heads are not trained.",
    }
    write_json(ROOT / config["report_output"], report)
    predictions_path = ROOT / config["predictions_output"]
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
