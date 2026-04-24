from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.training_common import load_config, load_dataset, load_tokenizer, optional_import_train_stack, pretrained_kwargs, resolve_local_model_source


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a trained sequence classifier on a JSONL dataset.")
    parser.add_argument("--config", required=True, help="Classifier training config for model/text-field metadata")
    parser.add_argument("--dataset", required=True, help="JSONL dataset to score")
    parser.add_argument("--output", required=True, help="Prediction JSONL output path")
    args = parser.parse_args()

    config = load_config(args.config)
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]

    local_files_only = bool(config.get("local_files_only"))
    tokenizer = load_tokenizer(
        transformers_module=transformers,
        model_name=config["model_name"],
        local_files_only=local_files_only,
    )
    model_source = resolve_local_model_source(config["output_dir"], local_files_only=True)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_source,
        **pretrained_kwargs(True),
    )
    model.config.pad_token_id = tokenizer.pad_token_id

    rows = load_dataset(args.dataset)
    text_field = config.get("text_field", "text")
    converted = [
        {
            "id": row["id"],
            "text": str(row.get(text_field) or row.get("prompt") or row.get("code") or ""),
            "label": int(bool(row.get("has_vulnerability"))),
        }
        for row in rows
    ]
    dataset = datasets.Dataset.from_list(converted)
    max_length = int(config["training_args"]["max_seq_length"])

    def tokenize_batch(batch: dict[str, list[object]]) -> dict[str, object]:
        tokenized = tokenizer(
            batch["text"],
            truncation=True,
            max_length=max_length,
            padding="max_length",
        )
        tokenized["labels"] = batch["label"]
        return tokenized

    dataset = dataset.map(tokenize_batch, batched=True, remove_columns=dataset.column_names)
    trainer = transformers.Trainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir="artifacts/tmp_classifier_scoring",
            report_to=[],
            per_device_eval_batch_size=config["training_args"]["per_device_train_batch_size"],
        ),
        processing_class=tokenizer,
    )
    raw_pred = trainer.predict(dataset)
    logits = raw_pred.predictions
    probs = torch.softmax(torch.tensor(logits), dim=-1)[:, 1].tolist()
    preds = [1 if prob >= 0.5 else 0 for prob in probs]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row, pred, prob in zip(converted, preds, probs):
            handle.write(
                json.dumps(
                    {
                        "id": row["id"],
                        "gold": row["label"],
                        "pred": int(pred),
                        "supported_probability": float(prob),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(json.dumps({"rows": len(converted), "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
