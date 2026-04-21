from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vrf.io_utils import write_json, write_jsonl
from vrf.training_common import load_config, load_dataset, optional_import_train_stack, resolve_local_model_source


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
    f1 = (2 * precision * vulnerable_recall / (precision + vulnerable_recall)) if (precision + vulnerable_recall) else 0.0
    balanced_accuracy = (vulnerable_recall + safe_specificity) / 2
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "label_accuracy": round(accuracy, 4),
        "vulnerable_recall": round(vulnerable_recall, 4),
        "safe_specificity": round(safe_specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def parse_thresholds(raw: str | None) -> list[float]:
    if not raw:
        return [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    return [float(item.strip()) for item in raw.split(",") if item.strip()]


def select_best(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    return max(rows, key=lambda row: (row[key], row["presence_accuracy"], row["safe_specificity"]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run threshold sweep for a trained CodeXGLUE classifier checkpoint.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--thresholds", default=None)
    parser.add_argument("--report-path", required=True)
    parser.add_argument("--predictions-path", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    checkpoint_path = args.checkpoint or config["output_dir"]
    thresholds = parse_thresholds(args.thresholds)

    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]

    try:
        from peft import PeftModel
    except ImportError as exc:
        raise RuntimeError("peft is required for classifier threshold evaluation") from exc

    pretrained_kwargs: dict[str, object] = {}
    if config.get("local_files_only"):
        pretrained_kwargs["local_files_only"] = True
    model_source = resolve_local_model_source(config["model_name"], bool(config.get("local_files_only")))

    tokenizer = transformers.AutoTokenizer.from_pretrained(checkpoint_path, **pretrained_kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base_model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_source,
        num_labels=2,
        **pretrained_kwargs,
    )
    model = PeftModel.from_pretrained(base_model, checkpoint_path)
    model.config.pad_token_id = tokenizer.pad_token_id
    model.eval()

    if torch.cuda.is_available():
        device = torch.device("cuda")
        model = model.to(device)
    else:
        device = torch.device("cpu")

    eval_rows = load_dataset(config["eval_dataset_path"])
    text_field = config.get("text_field", "code")
    batch_size = int(config.get("eval_batch_size", 8))
    max_length = int(config["training_args"]["max_seq_length"])

    raw_predictions: list[dict[str, Any]] = []
    for start in range(0, len(eval_rows), batch_size):
        batch = eval_rows[start : start + batch_size]
        texts = [str(row.get(text_field) or row.get("prompt") or "") for row in batch]
        encoded = tokenizer(
            texts,
            truncation=True,
            max_length=max_length,
            padding=True,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = model(**encoded).logits
            probs = torch.softmax(logits, dim=-1)[:, 1].detach().cpu().tolist()
        for row, prob in zip(batch, probs):
            raw_predictions.append(
                {
                    "id": row["id"],
                    "gold": int(bool(row.get("has_vulnerability"))),
                    "vuln_probability": round(float(prob), 6),
                }
            )

    sweep_rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        threshold_predictions = []
        for row in raw_predictions:
            threshold_predictions.append(
                {
                    "id": row["id"],
                    "gold": row["gold"],
                    "pred": int(row["vuln_probability"] >= threshold),
                    "threshold": threshold,
                }
            )
        metrics = compute_binary_metrics(threshold_predictions)
        metrics["threshold"] = round(threshold, 4)
        sweep_rows.append(metrics)

    payload = {
        "checkpoint": checkpoint_path,
        "thresholds": sweep_rows,
        "best_by_presence_accuracy": select_best(sweep_rows, "presence_accuracy"),
        "best_by_balanced_accuracy": select_best(sweep_rows, "balanced_accuracy"),
        "best_by_f1": select_best(sweep_rows, "f1"),
    }
    write_json(args.report_path, payload)
    write_jsonl(args.predictions_path, raw_predictions)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
