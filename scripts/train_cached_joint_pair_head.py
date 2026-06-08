from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.joint_pair_model import build_ordered_pair_records, summarize_ordered_pairs
from vrf.training_common import optional_import_train_stack


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a fast cached explicit pair head over frozen detector features.")
    parser.add_argument("--config", default="configs/research_primevul_cached_pair_head_qwen15b_v1.json")
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--max-eval-pairs", type=int)
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    seed = int(config["seed"])
    transformers.set_seed(seed)
    train_rows = build_ordered_pair_records(read_jsonl(ROOT / config["train_dataset"]))
    eval_rows = build_ordered_pair_records(read_jsonl(ROOT / config["eval_dataset"]))
    if args.max_train_pairs:
        train_rows = train_rows[: args.max_train_pairs]
    if args.max_eval_pairs:
        eval_rows = eval_rows[: args.max_eval_pairs]

    checkpoint = ROOT / config["init_checkpoint"]
    tokenizer = transformers.AutoTokenizer.from_pretrained(checkpoint, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(checkpoint, local_files_only=True)
    model.config.pad_token_id = tokenizer.pad_token_id
    model.to("cuda")
    model.eval()
    hidden_size = int(model.config.hidden_size)
    max_length = int(config["max_seq_length"])

    include_score_features = bool(config.get("include_score_features", False))

    def encode_records(records: list[dict[str, Any]], split: str) -> tuple[np.ndarray, np.ndarray]:
        features: list[np.ndarray] = []
        labels: list[int] = []
        batch_size = int(config["feature_batch_pairs"])
        started = time.perf_counter()
        with torch.no_grad():
            for start in range(0, len(records), batch_size):
                batch = records[start : start + batch_size]
                texts = []
                for row in batch:
                    texts.extend([row["text_0"], row["text_1"]])
                    labels.append(int(row["label"]))
                tokens = tokenizer(
                    texts,
                    truncation=True,
                    max_length=max_length,
                    padding=True,
                    pad_to_multiple_of=8,
                    return_tensors="pt",
                )
                tokens = {key: value.to("cuda") for key, value in tokens.items()}
                with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                    outputs = model(**tokens, output_hidden_states=True, return_dict=True)
                    hidden = outputs.hidden_states[-1]
                    last_indices = tokens["attention_mask"].sum(dim=1) - 1
                    pooled = hidden[torch.arange(hidden.shape[0], device="cuda"), last_indices]
                    paired = pooled.reshape(len(batch), 2, hidden_size).float()
                    h0, h1 = paired[:, 0], paired[:, 1]
                    feature_parts = [h0, h1, h0 - h1, h0 * h1]
                    if include_score_features:
                        logits = outputs.logits.reshape(len(batch), 2, 2).float()
                        probabilities = logits.softmax(dim=-1)
                        vuln_scores = probabilities[:, :, 1]
                        feature_parts.extend(
                            [
                                logits.flatten(start_dim=1),
                                probabilities.flatten(start_dim=1),
                                vuln_scores[:, 1:] - vuln_scores[:, :1],
                            ]
                        )
                    batch_features = torch.cat(feature_parts, dim=-1).cpu().numpy()
                features.append(batch_features)
                if start and start % int(config["progress_every_pairs"]) == 0:
                    elapsed = time.perf_counter() - started
                    print(f"encoded {split} {start}/{len(records)} pairs ({start / elapsed:.2f} pairs/s)", flush=True)
        return np.concatenate(features, axis=0), np.asarray(labels, dtype=np.int64)

    print(
        json.dumps(
            {
                "device": torch.cuda.get_device_name(0),
                "train": summarize_ordered_pairs(train_rows),
                "eval": summarize_ordered_pairs(eval_rows),
                "feature_batch_pairs": config["feature_batch_pairs"],
            }
        ),
        flush=True,
    )
    cache_path = ROOT / config["feature_cache"]
    if cache_path.exists() and not args.max_train_pairs and not args.max_eval_pairs:
        cache = np.load(cache_path)
        train_x, train_y = cache["train_x"], cache["train_y"]
        eval_x, eval_y = cache["eval_x"], cache["eval_y"]
        print(f"loaded cached features from {cache_path}", flush=True)
    else:
        train_x, train_y = encode_records(train_rows, "train")
        eval_x, eval_y = encode_records(eval_rows, "eval")
        if not args.max_train_pairs and not args.max_eval_pairs:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            np.savez(cache_path, train_x=train_x, train_y=train_y, eval_x=eval_x, eval_y=eval_y)
    del model
    torch.cuda.empty_cache()

    generator = torch.Generator(device="cpu").manual_seed(seed)
    pair_head = torch.nn.Sequential(
        torch.nn.LayerNorm(train_x.shape[1]),
        torch.nn.Linear(train_x.shape[1], int(config["pair_head"]["hidden_size"])),
        torch.nn.GELU(),
        torch.nn.Dropout(float(config["pair_head"]["dropout"])),
        torch.nn.Linear(int(config["pair_head"]["hidden_size"]), 2),
    ).to("cuda")
    optimizer = torch.optim.AdamW(
        pair_head.parameters(),
        lr=float(config["training"]["learning_rate"]),
        weight_decay=float(config["training"]["weight_decay"]),
    )
    validation_fraction = float(config["training"]["validation_fraction"])
    validation_mask = np.asarray(
        [
            int(hashlib.sha256(str(row["pair_key"]).encode("utf-8")).hexdigest()[:8], 16) % 10000
            < int(validation_fraction * 10000)
            for row in train_rows
        ],
        dtype=bool,
    )
    fit_x_t = torch.tensor(train_x[~validation_mask], dtype=torch.float32)
    fit_y_t = torch.tensor(train_y[~validation_mask], dtype=torch.long)
    validation_x_t = torch.tensor(train_x[validation_mask], dtype=torch.float32, device="cuda")
    validation_y_t = torch.tensor(train_y[validation_mask], dtype=torch.long, device="cuda")
    eval_x_t = torch.tensor(eval_x, dtype=torch.float32, device="cuda")
    eval_y_t = torch.tensor(eval_y, dtype=torch.long, device="cuda")
    batch_size = int(config["training"]["batch_size"])
    epochs = int(config["training"]["num_train_epochs"])
    best_accuracy = 0.0
    best_state = None
    best_epoch = 0
    for epoch in range(1, epochs + 1):
        order = torch.randperm(len(fit_x_t), generator=generator)
        total_loss = 0.0
        pair_head.train()
        for start in range(0, len(order), batch_size):
            indices = order[start : start + batch_size]
            x = fit_x_t[indices].to("cuda")
            y = fit_y_t[indices].to("cuda")
            logits = pair_head(x)
            loss = torch.nn.functional.cross_entropy(logits, y)
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(indices)
        pair_head.eval()
        with torch.no_grad():
            predictions = pair_head(validation_x_t).argmax(dim=-1)
            accuracy = float((predictions == validation_y_t).float().mean().cpu())
        if accuracy >= best_accuracy:
            best_accuracy = accuracy
            best_epoch = epoch
            best_state = {key: value.detach().cpu().clone() for key, value in pair_head.state_dict().items()}
        if epoch == 1 or epoch % int(config["training"]["logging_epochs"]) == 0:
            print(f"epoch={epoch} loss={total_loss / len(fit_x_t):.4f} validation_acc={accuracy:.4f}", flush=True)

    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    if best_state is not None:
        pair_head.load_state_dict(best_state)
    torch.save(pair_head.state_dict(), output_dir / "pair_head.pt")
    pair_head.eval()
    with torch.no_grad():
        logits = pair_head(eval_x_t)
        probabilities = logits.softmax(dim=-1).cpu().numpy()
        predictions = probabilities.argmax(axis=1)
        final_eval_accuracy = float((torch.tensor(predictions, device="cuda") == eval_y_t).float().mean().cpu())
    rows = []
    for row, gold, pred, probs in zip(eval_rows, eval_y.tolist(), predictions.tolist(), probabilities.tolist(), strict=True):
        rows.append(
            {
                "pair_key": row["pair_key"],
                "gold_index": gold,
                "pred_index": pred,
                "correct": gold == pred,
                "vulnerable_index_1_probability": float(probs[1]),
            }
        )
    report = {
        "status": "ok",
        "method": "cached_explicit_pair_representation_head",
        "model": config["model_name"],
        "init_checkpoint": config["init_checkpoint"],
        "seed": seed,
        "train": summarize_ordered_pairs(train_rows),
        "selection": {
            "fit_pairs": int((~validation_mask).sum()),
            "validation_pairs": int(validation_mask.sum()),
            "best_epoch": best_epoch,
            "best_validation_accuracy": best_accuracy,
        },
        "eval": summarize_ordered_pairs(eval_rows),
        "include_score_features": include_score_features,
        "metrics": {
            "pair_orientation_accuracy": final_eval_accuracy,
            "group_all_correct": final_eval_accuracy,
        },
        "claim_boundary": "Frozen-detector representation probe. Epoch selection uses a train-derived validation split; the held-out eval is scored once after selection.",
    }
    write_json(ROOT / config["report_output"], report)
    predictions_path = ROOT / config["predictions_output"]
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
