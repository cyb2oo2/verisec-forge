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


def compute_eval_metrics(
    rows: list[dict[str, Any]], predictions: np.ndarray
) -> dict[str, float | int]:
    labels = np.asarray([int(row["label"]) for row in rows])
    predicted = predictions.argmax(axis=-1)
    total = int(len(labels))
    correct = int((predicted == labels).sum())
    positive = labels == 1
    negative = labels == 0
    true_positive = int(((predicted == 1) & positive).sum())
    true_negative = int(((predicted == 0) & negative).sum())
    false_positive = int(((predicted == 1) & negative).sum())
    false_negative = int(((predicted == 0) & positive).sum())
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    specificity = (
        true_negative / (true_negative + false_positive)
        if true_negative + false_positive
        else 0.0
    )
    return {
        "rows": total,
        "accuracy": correct / total if total else 0.0,
        "precision_b": precision,
        "recall_b": recall,
        "specificity_a": specificity,
        "tp": true_positive,
        "tn": true_negative,
        "fp": false_positive,
        "fn": false_negative,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train the PR #12A non-Qwen decoder classifier slot."
    )
    parser.add_argument(
        "--config",
        default="configs/research_cross_model_decoder_distilgpt2_v1.json",
    )
    parser.add_argument("--max-train-examples", type=int)
    parser.add_argument("--max-eval-examples", type=int)
    parser.add_argument("--local-files-only", action="store_true")
    args = parser.parse_args()

    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))
    if "qwen" in str(config["model_name"]).lower():
        raise ValueError("PR #12A decoder replication must not use Qwen family.")

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import LoraConfig, TaskType, get_peft_model

    seed = int(config["seed"])
    transformers.set_seed(seed)
    model_source = resolve_local_model_source(
        config["model_name"], args.local_files_only
    )
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        model_source,
        local_files_only=args.local_files_only,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"

    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_source,
        num_labels=2,
        local_files_only=args.local_files_only,
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    if hasattr(model.config, "use_cache"):
        model.config.use_cache = False

    peft = config["peft"]
    model = get_peft_model(
        model,
        LoraConfig(
            r=int(peft["r"]),
            lora_alpha=int(peft["lora_alpha"]),
            lora_dropout=float(peft["lora_dropout"]),
            target_modules=list(peft["target_modules"]),
            modules_to_save=["score"],
            bias="none",
            task_type=TaskType.SEQ_CLS,
        ),
    )

    train_rows = read_jsonl(ROOT / config["train_dataset"])
    eval_rows = read_jsonl(ROOT / config["eval_dataset"])
    if args.max_train_examples:
        train_rows = train_rows[: args.max_train_examples]
    if args.max_eval_examples:
        eval_rows = eval_rows[: args.max_eval_examples]

    max_length = int(config["max_seq_length"])

    def tokenize(batch: dict[str, list[Any]]) -> dict[str, Any]:
        encoded = tokenizer(
            batch["text"],
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        encoded["labels"] = [int(label) for label in batch["label"]]
        return encoded

    train_dataset = datasets.Dataset.from_list(train_rows)
    eval_dataset = datasets.Dataset.from_list(eval_rows)
    train_dataset = train_dataset.map(
        tokenize, batched=True, remove_columns=train_dataset.column_names
    )
    eval_dataset = eval_dataset.map(
        tokenize, batched=True, remove_columns=eval_dataset.column_names
    )

    training = config["training"]
    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    steps_per_epoch = math.ceil(
        len(train_rows)
        / (
            int(training["per_device_train_batch_size"])
            * int(training["gradient_accumulation_steps"])
        )
    )
    print(
        "non-Qwen decoder classifier: "
        f"model={config['model_name']} train={len(train_rows)} "
        f"eval={len(eval_rows)} steps/epoch={steps_per_epoch} "
        f"max_length={max_length}",
        flush=True,
    )

    trainer = transformers.Trainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=float(training["num_train_epochs"]),
            learning_rate=float(training["learning_rate"]),
            per_device_train_batch_size=int(
                training["per_device_train_batch_size"]
            ),
            per_device_eval_batch_size=int(
                training["per_device_eval_batch_size"]
            ),
            gradient_accumulation_steps=int(
                training["gradient_accumulation_steps"]
            ),
            logging_steps=int(training["logging_steps"]),
            save_strategy="no",
            eval_strategy="no",
            fp16=False,
            bf16=bool(torch.cuda.is_available()),
            gradient_checkpointing=False,
            report_to=[],
            seed=seed,
            data_seed=seed,
            remove_unused_columns=True,
        ),
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=transformers.DataCollatorWithPadding(
            tokenizer=tokenizer,
            pad_to_multiple_of=8,
        ),
    )
    trainer.train()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    raw = trainer.predict(eval_dataset)
    logits = np.asarray(raw.predictions)
    report = {
        "status": "ok",
        "model": config["model_name"],
        "checkpoint": config["output_dir"],
        "seed": seed,
        "train_rows": len(train_rows),
        "eval_rows": len(eval_rows),
        "metrics": compute_eval_metrics(eval_rows, logits),
        "claim_boundary": config["claim_boundary"],
    }
    write_json(ROOT / config["report_output"], report)
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
