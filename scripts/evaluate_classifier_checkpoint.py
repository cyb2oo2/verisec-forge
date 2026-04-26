from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.train_eval_codexglue_classifier import compute_binary_metrics
from vrf.io_utils import write_json
from vrf.training_common import load_config, load_dataset, optional_import_train_stack, resolve_local_model_source


def convert_rows(rows: list[dict[str, Any]], text_field: str) -> list[dict[str, Any]]:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate an existing sequence-classifier checkpoint.")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    transformers = stack["transformers"]

    checkpoint_dir = Path(config.get("checkpoint_dir") or config["output_dir"])
    pretrained_kwargs: dict[str, object] = {}
    if config.get("local_files_only"):
        pretrained_kwargs["local_files_only"] = True

    tokenizer_source = checkpoint_dir if checkpoint_dir.exists() else resolve_local_model_source(
        config["model_name"],
        bool(config.get("local_files_only")),
    )
    tokenizer = transformers.AutoTokenizer.from_pretrained(tokenizer_source, **pretrained_kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    try:
        from peft import AutoPeftModelForSequenceClassification

        model = AutoPeftModelForSequenceClassification.from_pretrained(
            checkpoint_dir,
            **pretrained_kwargs,
        )
    except Exception:
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            checkpoint_dir,
            num_labels=2,
            **pretrained_kwargs,
        )
    model.config.pad_token_id = tokenizer.pad_token_id

    text_field = config.get("text_field", "code")
    eval_rows = load_dataset(config["eval_dataset_path"])
    converted_eval_rows = convert_rows(eval_rows, text_field)
    eval_dataset = datasets.Dataset.from_list(converted_eval_rows)
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

    eval_dataset = eval_dataset.map(tokenize_batch, batched=True, remove_columns=eval_dataset.column_names)
    training_args = transformers.TrainingArguments(
        output_dir=str(checkpoint_dir),
        per_device_eval_batch_size=int(config["training_args"].get("per_device_eval_batch_size", 1)),
        report_to=[],
        remove_unused_columns=False,
        fp16=False,
        bf16=False,
    )
    trainer = transformers.Trainer(model=model, args=training_args, processing_class=tokenizer)
    raw_pred = trainer.predict(eval_dataset)
    logits = raw_pred.predictions
    labels = raw_pred.label_ids
    preds = logits.argmax(axis=-1)
    shifted_logits = logits - logits.max(axis=-1, keepdims=True)
    probabilities = np.exp(shifted_logits) / np.exp(shifted_logits).sum(axis=-1, keepdims=True)

    prediction_rows: list[dict[str, Any]] = []
    for idx, pred in enumerate(preds.tolist()):
        prediction_rows.append(
            {
                "id": converted_eval_rows[idx]["id"],
                "gold": int(labels[idx]),
                "pred": int(pred),
                "vuln_probability": float(probabilities[idx][1]),
            }
        )

    metrics = compute_binary_metrics(prediction_rows)
    write_json(config["report_path"], metrics)

    predictions_path = Path(config["predictions_path"])
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in prediction_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
