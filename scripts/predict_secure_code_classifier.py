from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from vrf.io_utils import read_jsonl, write_json
from vrf.training_common import optional_import_train_stack


def compute_binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 1)
    tn = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 0)
    fp = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 1)
    fn = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 0)
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "label_accuracy": round(accuracy, 4),
        "vulnerable_recall": round(recall, 4),
        "safe_specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run prediction with a saved PEFT sequence-classification checkpoint.")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--text-field", default="pair_text")
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--predictions-output", required=True)
    parser.add_argument("--report-output", required=True)
    args = parser.parse_args()

    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]
    try:
        from peft import AutoPeftModelForSequenceClassification
    except ImportError as exc:
        raise RuntimeError("peft is required for checkpoint prediction") from exc

    rows = read_jsonl(args.dataset)
    tokenizer = transformers.AutoTokenizer.from_pretrained(args.checkpoint, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(args.checkpoint, local_files_only=True)
    model.config.pad_token_id = tokenizer.pad_token_id
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    prediction_rows: list[dict[str, Any]] = []
    for start in range(0, len(rows), args.batch_size):
        if start and start % 100 == 0:
            print(f"predicted {start}/{len(rows)}")
        batch_rows = rows[start : start + args.batch_size]
        texts = [str(row.get(args.text_field) or row.get("prompt") or row.get("code") or "") for row in batch_rows]
        tokenized = tokenizer(
            texts,
            truncation=True,
            max_length=args.max_seq_length,
            padding=True,
            return_tensors="pt",
        )
        tokenized = {key: value.to(device) for key, value in tokenized.items()}
        with torch.no_grad():
            logits = model(**tokenized).logits.float().detach().cpu().numpy()
        shifted = logits - logits.max(axis=-1, keepdims=True)
        probabilities = np.exp(shifted) / np.exp(shifted).sum(axis=-1, keepdims=True)
        for row, probability in zip(batch_rows, probabilities, strict=True):
            vuln_probability = float(probability[1])
            gold = int(bool(row.get("has_vulnerability")))
            prediction_rows.append(
                {
                    "id": row["id"],
                    "gold": gold,
                    "pred": int(vuln_probability >= args.threshold),
                    "vuln_probability": vuln_probability,
                }
            )

    Path(args.predictions_output).parent.mkdir(parents=True, exist_ok=True)
    with Path(args.predictions_output).open("w", encoding="utf-8") as handle:
        for row in prediction_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    report = compute_binary_metrics(prediction_rows)
    write_json(args.report_output, report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
