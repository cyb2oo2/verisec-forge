from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vrf.io_utils import write_json
from vrf.schemas import ExperimentRecord
from vrf.tracking import log_experiment
from vrf.training_common import (
    cpu_training_overrides,
    ensure_output_dir,
    load_config,
    load_dataset,
    optional_import_train_stack,
    resolve_local_model_source,
)


def compute_binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 1)
    tn = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 0)
    fp = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 1)
    fn = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 0)
    accuracy = (tp + tn) / total if total else 0.0
    vulnerable_recall = tp / (tp + fn) if (tp + fn) else 0.0
    safe_specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "label_accuracy": round(accuracy, 4),
        "vulnerable_recall": round(vulnerable_recall, 4),
        "safe_specificity": round(safe_specificity, 4),
        "precision": round(precision, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate a discriminative CodeXGLUE classifier baseline.")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    ensure_output_dir(config["output_dir"])

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]

    try:
        from peft import LoraConfig, TaskType, get_peft_model
    except ImportError as exc:
        raise RuntimeError("peft is required for classifier baseline runs") from exc

    pretrained_kwargs: dict[str, object] = {}
    if config.get("local_files_only"):
        pretrained_kwargs["local_files_only"] = True
    model_source = resolve_local_model_source(config["model_name"], bool(config.get("local_files_only")))

    tokenizer = transformers.AutoTokenizer.from_pretrained(model_source, **pretrained_kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model_kwargs: dict[str, object] = {"num_labels": 2}
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_source,
        **model_kwargs,
        **pretrained_kwargs,
    )
    model.config.pad_token_id = tokenizer.pad_token_id

    peft_cfg = config.get("peft", {})
    if peft_cfg.get("enabled"):
        peft_config = LoraConfig(
            r=peft_cfg["r"],
            lora_alpha=peft_cfg["lora_alpha"],
            lora_dropout=peft_cfg["lora_dropout"],
            target_modules=peft_cfg["target_modules"],
            bias="none",
            task_type=TaskType.SEQ_CLS,
        )
        model = get_peft_model(model, peft_config)

    text_field = config.get("text_field", "code")
    train_rows = load_dataset(config["train_dataset_path"])
    eval_rows = load_dataset(config["eval_dataset_path"])

    def convert_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted: list[dict[str, Any]] = []
        for row in rows:
            converted.append(
                {
                    "id": row["id"],
                    "text": str(row.get(text_field) or row.get("prompt") or ""),
                    "label": int(bool(row.get("has_vulnerability"))),
                }
            )
        return converted

    train_dataset = datasets.Dataset.from_list(convert_rows(train_rows))
    eval_dataset = datasets.Dataset.from_list(convert_rows(eval_rows))

    max_length = int(config["training_args"]["max_seq_length"])

    def tokenize_batch(batch: dict[str, list[Any]]) -> dict[str, Any]:
        tokenized = tokenizer(
            batch["text"],
            truncation=True,
            max_length=max_length,
            padding="max_length",
        )
        tokenized["labels"] = batch["label"]
        return tokenized

    train_dataset = train_dataset.map(tokenize_batch, batched=True, remove_columns=train_dataset.column_names)
    eval_dataset = eval_dataset.map(tokenize_batch, batched=True, remove_columns=eval_dataset.column_names)

    precision_overrides = cpu_training_overrides(torch)
    precision_overrides["fp16"] = False
    precision_overrides["bf16"] = False

    training_args = transformers.TrainingArguments(
        output_dir=config["output_dir"],
        num_train_epochs=config["training_args"]["num_train_epochs"],
        learning_rate=config["training_args"]["learning_rate"],
        per_device_train_batch_size=config["training_args"]["per_device_train_batch_size"],
        per_device_eval_batch_size=config["training_args"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training_args"]["gradient_accumulation_steps"],
        logging_steps=config["training_args"]["logging_steps"],
        save_steps=config["training_args"]["save_steps"],
        report_to=[],
        remove_unused_columns=False,
        **precision_overrides,
    )

    trainer = transformers.Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
    )
    trainer.train()
    trainer.save_model(config["output_dir"])
    tokenizer.save_pretrained(config["output_dir"])

    raw_pred = trainer.predict(eval_dataset)
    logits = raw_pred.predictions
    labels = raw_pred.label_ids
    preds = logits.argmax(axis=-1)

    prediction_rows: list[dict[str, Any]] = []
    for idx, pred in enumerate(preds.tolist()):
        gold = int(labels[idx])
        prediction_rows.append(
            {
                "id": convert_rows(eval_rows)[idx]["id"],
                "gold": gold,
                "pred": int(pred),
            }
        )

    metrics = compute_binary_metrics(prediction_rows)
    write_json(config["report_path"], metrics)

    predictions_path = Path(config["predictions_path"])
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in prediction_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    if config.get("tracker_path"):
        log_experiment(
            ExperimentRecord(
                stage="cls_baseline",
                model_name=config["model_name"],
                config_path=args.config,
                artifact_path=config["output_dir"],
                metrics=metrics,
            ),
            config["tracker_path"],
        )

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
