from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def run_inference(
    *,
    checkpoint: str,
    rows: list[dict[str, Any]],
    max_seq_length: int,
    batch_size: int,
    threshold: float,
) -> list[dict[str, Any]]:
    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the CrossVul zero-shot evaluation")

    tokenizer = AutoTokenizer.from_pretrained(checkpoint, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(checkpoint, local_files_only=True)
    model.config.pad_token_id = tokenizer.pad_token_id
    device = torch.device("cuda")
    model.to(device)
    model.eval()

    ordered = sorted(rows, key=lambda row: len(str(row.get("pair_text") or "")))
    predictions: list[dict[str, Any]] = []
    started = time.perf_counter()
    for start in range(0, len(ordered), batch_size):
        batch = ordered[start : start + batch_size]
        tokenized = tokenizer(
            [str(row["pair_text"]) for row in batch],
            truncation=True,
            max_length=max_seq_length,
            padding=True,
            return_tensors="pt",
        )
        tokenized = {key: value.to(device, non_blocking=True) for key, value in tokenized.items()}
        with torch.inference_mode():
            logits = model(**tokenized).logits.float()
            probabilities = torch.softmax(logits, dim=-1)[:, 1].cpu().tolist()
        for row, probability in zip(batch, probabilities, strict=True):
            predictions.append(
                {
                    "id": row["id"],
                    "pair_key": row.get("pair_key"),
                    "vuln_probability": float(probability),
                    "gold": int(bool(row.get("has_vulnerability"))),
                    "pred": int(probability >= threshold),
                    "project": row.get("project"),
                    "cwe": row.get("cwe"),
                    "vulnerability_type": row.get("vulnerability_type"),
                    "changed_line_bucket": row.get("changed_line_bucket"),
                    "programming_language": row.get("programming_language"),
                }
            )
        if (start // batch_size) % 20 == 0 or start + batch_size >= len(ordered):
            elapsed = max(time.perf_counter() - started, 1e-9)
            processed = min(start + batch_size, len(ordered))
            print(f"progress {processed}/{len(ordered)} rate={processed / elapsed:.1f} rows/s", flush=True)
    return predictions


def build_report(
    predictions: list[dict[str, Any]],
    *,
    threshold: float,
    margin: float,
    checkpoint_label: str,
) -> dict[str, Any]:
    pair_rows, coupling_counts = apply_pair_coupling(predictions, margin=margin)
    labels = Counter(int(row["gold"]) for row in predictions)
    buckets = Counter(str(row.get("changed_line_bucket") or "unknown") for row in predictions)
    return {
        "status": "ok",
        "scope": "crossvul_zero_shot_primevul_checkpoint",
        "protocol": {
            "source_dataset": "crossvul (data/raw/crossvul_train_raw.jsonl, c/cpp only)",
            "checkpoint": checkpoint_label,
            "threshold": threshold,
            "pair_coupling_margin": margin,
            "target_training": "none; CrossVul was never used in training, development, or model selection for this checkpoint",
        },
        "split": {
            "rows": len(predictions),
            "unique_pair_count": len({str(row.get("pair_key") or row["id"]) for row in predictions}),
            "label_counts": {"safe": labels.get(0, 0), "vulnerable": labels.get(1, 0)},
            "changed_line_buckets": dict(sorted(buckets.items())),
        },
        "default_threshold": {
            "overall": compute_binary_metrics(predictions),
            "group_metrics": compute_group_metrics(predictions),
        },
        "pair_coupled": {
            "overall": compute_binary_metrics(pair_rows),
            "group_metrics": compute_group_metrics(pair_rows),
            "coupling_counts": coupling_counts,
        },
    }


def _row(name: str, overall: dict[str, Any], group: dict[str, Any]) -> str:
    return (
        f"| `{name}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
        f"`{overall['safe_specificity']}` | `{overall['precision']}` | `{overall['f1']}` | "
        f"`{group['group_all_correct_rate']}` | `{group['orientation_accuracy']}` |"
    )


def render_report(report: dict[str, Any]) -> str:
    default = report["default_threshold"]
    pair = report["pair_coupled"]
    return "\n".join(
        [
            "# CrossVul Open-Set Zero-Shot Transfer Evaluation",
            "",
            "This report evaluates the headline PrimeVul-trained paired-diff detector directly on",
            "CrossVul C/C++ paired vulnerable/secure snapshots -- a source this checkpoint has never",
            "seen in training, development, or model selection. PrimeVul, DeltaSecommits, and",
            "PatchEval are the project's three existing sources; CrossVul is a genuine fourth, isolating",
            "open-set source shift from the closed-world routing already characterized in",
            "`reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`.",
            "",
            "## Protocol",
            "",
            f"- Source dataset: `{report['protocol']['source_dataset']}`",
            f"- Checkpoint: `{report['protocol']['checkpoint']}`",
            f"- Threshold: `{report['protocol']['threshold']}`",
            f"- Pair-coupling margin: `{report['protocol']['pair_coupling_margin']}`",
            "",
            "## Split",
            "",
            f"- Rows: `{report['split']['rows']}`",
            f"- Pair groups: `{report['split']['unique_pair_count']}`",
            f"- Safe/vulnerable: `{report['split']['label_counts']['safe']}/{report['split']['label_counts']['vulnerable']}`",
            "",
            "## Results",
            "",
            "| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            _row("default threshold", default["overall"], default["group_metrics"]),
            _row("pair-coupled", pair["overall"], pair["group_metrics"]),
            "",
            "## Interpretation",
            "",
            "This is the project's first genuine open-set source-shift check: CrossVul was not used",
            "anywhere in this checkpoint's training, development, or model selection, unlike the",
            "closed-world router stress tests. If balanced accuracy is well below the PrimeVul/",
            "DeltaSecommits/PatchEval range, that is useful negative evidence bounding the paired-diff",
            "formulation's generalization, not evidence the formulation is wrong -- CrossVul pairs come",
            "from different repositories, commit conventions, and CWE distributions than any source the",
            "detector has seen.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CrossVul open-set zero-shot transfer from the headline PrimeVul paired-diff checkpoint.")
    parser.add_argument("--metadata", default="data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--checkpoint", default="checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1")
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--predictions-output", default="outputs/secure_code_crossvul_zero_shot_primevul_checkpoint_predictions.jsonl")
    parser.add_argument("--json-output", default="reports/secure_code_crossvul_zero_shot_primevul_checkpoint_eval_v1.json")
    parser.add_argument("--md-output", default="reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    rows = read_jsonl(ROOT / args.metadata)
    if args.limit:
        rows = rows[: args.limit]

    predictions = run_inference(
        checkpoint=str(ROOT / args.checkpoint),
        rows=rows,
        max_seq_length=args.max_seq_length,
        batch_size=args.batch_size,
        threshold=args.threshold,
    )
    from vrf.io_utils import write_jsonl

    write_jsonl(ROOT / args.predictions_output, predictions)

    report = build_report(
        predictions,
        threshold=args.threshold,
        margin=args.pair_margin,
        checkpoint_label=args.checkpoint,
    )
    write_json(ROOT / args.json_output, report)
    ensure_parent(ROOT / args.md_output).write_text(render_report(report), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items()}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
