from __future__ import annotations

import argparse
import hashlib
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
from vrf.counterfactuals import add_nonsecurity_padding, normalize_code_identifiers
from vrf.joint_reasoning import reverse_side_choice_text
from vrf.gpu_budget import apply_gpu_budget, describe, throttle_callback
from vrf.training_common import optional_import_train_stack, quantization_kwargs


def pair_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[int, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["pair_key"]), {})[int(row["label"])] = row
    return [
        {
            "pair_key": pair_key,
            "safe_candidate_text": sides[0]["text"],
            "vulnerable_candidate_text": sides[1]["text"],
            "pair_length": max(len(sides[0]["text"]), len(sides[1]["text"])),
        }
        for pair_key, sides in sorted(grouped.items())
        if set(sides) == {0, 1}
    ]


def nuisance_transform(text: str, intervention: str) -> str:
    if intervention == "identifier_normalized":
        return normalize_code_identifiers(text)
    if intervention == "nonsecurity_padding":
        return add_nonsecurity_padding(text)
    raise ValueError(f"Unsupported nuisance intervention: {intervention}")


def select_nuisance_intervention(pair_key: str, interventions: list[str]) -> str:
    digest = hashlib.sha256(pair_key.encode("utf-8")).digest()
    return interventions[int.from_bytes(digest[:4], "big") % len(interventions)]


def deterministic_pair_subset(rows: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    if not limit or limit >= len(rows):
        return rows
    return sorted(
        rows,
        key=lambda row: hashlib.sha256(str(row["pair_key"]).encode("utf-8")).hexdigest(),
    )[:limit]


def length_bucket_order(
    rows: list[dict[str, Any]],
    *,
    seed: int,
    bucket_size: int = 32,
) -> list[dict[str, Any]]:
    ordered = sorted(rows, key=lambda row: int(row["pair_length"]))
    buckets = [ordered[start : start + bucket_size] for start in range(0, len(ordered), bucket_size)]
    rng = random.Random(seed)
    for bucket in buckets:
        rng.shuffle(bucket)
    rng.shuffle(buckets)
    return [row for bucket in buckets for row in bucket]


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a pairwise joint side-choice model.")
    parser.add_argument("--config", default="configs/research_primevul_joint_pairwise_qwen15b_v1.json")
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--max-eval-pairs", type=int)
    parser.add_argument("--skip-training", action="store_true")
    parser.add_argument("--evaluation-checkpoint")
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    seed = int(config["seed"])
    transformers.set_seed(seed)
    tokenizer = transformers.AutoTokenizer.from_pretrained(config["init_checkpoint"], local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    load_checkpoint = args.evaluation_checkpoint or config["init_checkpoint"]
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        ROOT / load_checkpoint,
        local_files_only=True,
        is_trainable=True,
        **quantization_kwargs(config, torch),
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.enable_input_require_grads()

    train_pairs = pair_records(read_jsonl(ROOT / config["train_dataset"]))
    eval_pairs = pair_records(read_jsonl(ROOT / config["eval_dataset"]))
    train_limit = args.max_train_pairs or config.get("max_train_pairs")
    if train_limit:
        train_pairs = deterministic_pair_subset(train_pairs, int(train_limit))
    train_pairs = length_bucket_order(train_pairs, seed=seed)
    if args.max_eval_pairs:
        eval_pairs = eval_pairs[: args.max_eval_pairs]
    train_dataset = datasets.Dataset.from_list(train_pairs)

    max_length = int(config["max_seq_length"])

    class PairCollator:
        def __call__(self, features: list[dict[str, Any]]) -> dict[str, Any]:
            texts = []
            consistency_weight = float(config["loss"].get("synthetic_consistency_weight", 0.0))
            nuisance_weight = float(config["loss"].get("nuisance_consistency_weight", 0.0))
            nuisance_interventions = list(config["loss"].get("nuisance_interventions", []))
            for feature in features:
                texts.extend([feature["safe_candidate_text"], feature["vulnerable_candidate_text"]])
                if consistency_weight:
                    texts.extend(
                        [
                            reverse_side_choice_text(feature["safe_candidate_text"]),
                            reverse_side_choice_text(feature["vulnerable_candidate_text"]),
                        ]
                    )
                if nuisance_weight:
                    intervention = select_nuisance_intervention(
                        feature["pair_key"],
                        nuisance_interventions,
                    )
                    texts.extend(
                        [
                            nuisance_transform(feature["safe_candidate_text"], intervention),
                            nuisance_transform(feature["vulnerable_candidate_text"], intervention),
                        ]
                    )
            encoded = tokenizer(
                texts,
                truncation=True,
                max_length=max_length,
                padding=True,
                pad_to_multiple_of=8,
                return_tensors="pt",
            )
            encoded["pair_labels"] = torch.tensor([[0, 1]] * len(features), dtype=torch.long)
            return encoded

    class PairwiseTrainer(transformers.Trainer):
        def _get_train_sampler(self, train_dataset=None):
            return torch.utils.data.SequentialSampler(train_dataset or self.train_dataset)

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("pair_labels")
            outputs = model(**inputs)
            consistency_weight = float(config["loss"].get("synthetic_consistency_weight", 0.0))
            nuisance_weight = float(config["loss"].get("nuisance_consistency_weight", 0.0))
            orientations = 2 + (2 if consistency_weight else 0) + (2 if nuisance_weight else 0)
            logits = outputs.logits.reshape(labels.shape[0], orientations, 2)
            real_logits = logits[:, :2]
            classification = torch.nn.functional.cross_entropy(real_logits.reshape(-1, 2), labels.reshape(-1))
            vulnerable_scores = real_logits[:, :, 1]
            margin = torch.relu(float(config["loss"]["margin"]) - (vulnerable_scores[:, 1] - vulnerable_scores[:, 0])).mean()
            probabilities = real_logits.softmax(dim=-1)[:, :, 1]
            complement = ((probabilities.sum(dim=1) - 1.0) ** 2).mean()
            loss = (
                classification
                + float(config["loss"]["margin_weight"]) * margin
                + float(config["loss"]["complement_weight"]) * complement
            )
            # Both extras are applied together (a "protected" objective) rather than
            # mutually exclusive, so padding-invariance adaptation cannot trade off
            # against the synthetic side-order consistency signal.
            offset = 2
            if consistency_weight:
                all_probabilities = logits.softmax(dim=-1)[:, :, 1]
                consistency = (
                    torch.nn.functional.mse_loss(all_probabilities[:, offset], all_probabilities[:, 1])
                    + torch.nn.functional.mse_loss(all_probabilities[:, offset + 1], all_probabilities[:, 0])
                ) / 2
                loss = loss + consistency_weight * consistency
                offset += 2
            if nuisance_weight:
                nuisance_logits = logits[:, offset : offset + 2]
                nuisance_probabilities = nuisance_logits.softmax(dim=-1)[:, :, 1]
                nuisance_classification = torch.nn.functional.cross_entropy(
                    nuisance_logits.reshape(-1, 2),
                    labels.reshape(-1),
                )
                nuisance_consistency = torch.nn.functional.mse_loss(
                    nuisance_probabilities,
                    probabilities,
                )
                loss = (
                    loss
                    + float(config["loss"].get("nuisance_classification_weight", 0.5))
                    * nuisance_classification
                    + nuisance_weight * nuisance_consistency
                )
                offset += 2
            return (loss, outputs) if return_outputs else loss

    training = config["training"]
    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    steps = math.ceil(
        len(train_pairs)
        / (int(training["per_device_train_batch_size"]) * int(training["gradient_accumulation_steps"]))
    )
    print(
        f"joint pairwise: train_pairs={len(train_pairs)} eval_pairs={len(eval_pairs)} "
        f"steps/epoch={steps} max_length={max_length} device={torch.cuda.get_device_name(0)}",
        flush=True,
    )
    trainer = PairwiseTrainer(
        model=model,
        args=transformers.TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=float(training["num_train_epochs"]),
            learning_rate=float(training["learning_rate"]),
            per_device_train_batch_size=int(training["per_device_train_batch_size"]),
            gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
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
    print(describe(apply_gpu_budget(torch)), flush=True)
    pacing = throttle_callback(transformers)
    if pacing is not None:
        trainer.add_callback(pacing)
    if not args.skip_training:
        trainer.train()
        trainer.save_model(str(output_dir))
        tokenizer.save_pretrained(str(output_dir))

    device = trainer.model.device
    trainer.model.eval()
    predictions = []
    batch_size = int(training["per_device_eval_batch_size"])
    eval_pairs_by_length = sorted(eval_pairs, key=lambda row: int(row["pair_length"]))
    for start in range(0, len(eval_pairs_by_length), batch_size):
        batch = eval_pairs_by_length[start : start + batch_size]
        texts = []
        for row in batch:
            texts.extend([row["safe_candidate_text"], row["vulnerable_candidate_text"]])
        encoded = tokenizer(
            texts,
            truncation=True,
            max_length=max_length,
            padding=True,
            pad_to_multiple_of=8,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = trainer.model(**encoded).logits.float().cpu().numpy().reshape(len(batch), 2, 2)
        probabilities = np.exp(logits - logits.max(axis=2, keepdims=True))
        probabilities = probabilities / probabilities.sum(axis=2, keepdims=True)
        for row, probs in zip(batch, probabilities, strict=True):
            safe_score = float(probs[0, 1])
            vulnerable_score = float(probs[1, 1])
            predictions.append(
                {
                    "pair_key": row["pair_key"],
                    "safe_candidate_probability": safe_score,
                    "vulnerable_candidate_probability": vulnerable_score,
                    "correct_orientation": vulnerable_score > safe_score,
                    "independent_both_correct": safe_score < 0.5 <= vulnerable_score,
                }
            )
        if start and (start // batch_size) % 10 == 0:
            print(f"evaluated {start}/{len(eval_pairs_by_length)} pairs", flush=True)

    orientation = sum(row["correct_orientation"] for row in predictions) / len(predictions)
    independent = sum(row["independent_both_correct"] for row in predictions) / len(predictions)
    report = {
        "status": "ok",
        "method": "learned_pairwise_joint_side_choice",
        "model": config["model_name"],
        "init_checkpoint": config["init_checkpoint"],
        "checkpoint": load_checkpoint if args.skip_training else config["output_dir"],
        "seed": seed,
        "training_skipped": args.skip_training,
        "protocol": {
            "checkpoint_training_scope": config.get("checkpoint_training_scope", "full_configured_training"),
            "train_pairs": len(train_pairs),
            "eval_pairs": len(eval_pairs),
            "max_seq_length": max_length,
            "nuisance_interventions": list(config["loss"].get("nuisance_interventions", [])),
            "nuisance_intervention_counts": {
                intervention: sum(
                    select_nuisance_intervention(
                        row["pair_key"],
                        list(config["loss"].get("nuisance_interventions", [])),
                    )
                    == intervention
                    for row in train_pairs
                )
                for intervention in config["loss"].get("nuisance_interventions", [])
            },
        },
        "metrics": {
            "unique_pairs": len(predictions),
            "pair_orientation_accuracy": orientation,
            "joint_group_all_correct": orientation,
            "joint_side_swap_equivariance": 1.0,
            "independent_threshold_group_all_correct": independent,
        },
        "claim_boundary": "The 1.0 equivariance is enforced by pairwise joint decoding, not learned standalone invariance.",
    }
    report_path = ROOT / config["report_output"]
    predictions_path = ROOT / config["predictions_output"]
    if args.skip_training and not args.evaluation_checkpoint:
        report_path = report_path.with_name(report_path.stem + "_zero_shot" + report_path.suffix)
        predictions_path = predictions_path.with_name(predictions_path.stem + "_zero_shot" + predictions_path.suffix)
    write_json(report_path, report)
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
