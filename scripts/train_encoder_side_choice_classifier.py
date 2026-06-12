from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.training_common import optional_import_train_stack


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train an encoder-style pair side-choice classifier."
    )
    parser.add_argument(
        "--config",
        default="configs/research_primevul_joint_side_choice_codebert_v1.json",
    )
    parser.add_argument("--max-train-examples", type=int)
    args = parser.parse_args()
    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))

    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    transformers.set_seed(int(config["seed"]))

    model_path = ROOT / config["model_path"]
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        model_path, local_files_only=True
    )
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_path,
        num_labels=2,
        local_files_only=True,
    )
    train_rows = read_jsonl(ROOT / config["train_dataset"])
    if args.max_train_examples:
        train_rows = train_rows[: args.max_train_examples]

    def tokenize(batch):
        encoded = tokenizer(
            batch["text"],
            truncation=True,
            max_length=int(config["max_seq_length"]),
            padding=False,
        )
        encoded["labels"] = batch["label"]
        return encoded

    train_dataset = datasets.Dataset.from_list(train_rows)
    train_dataset = train_dataset.map(
        tokenize,
        batched=True,
        remove_columns=train_dataset.column_names,
    )
    train_dataset.set_format(
        type="torch",
        columns=["input_ids", "attention_mask", "labels"],
    )

    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    training = config["training"]
    effective_batch = int(training["per_device_train_batch_size"]) * int(
        training["gradient_accumulation_steps"]
    )
    steps = math.ceil(len(train_rows) / effective_batch)
    print(
        f"encoder side choice: train={len(train_rows)} "
        f"steps/epoch={steps} max_length={config['max_seq_length']} "
        f"device={torch.cuda.get_device_name(0)}",
        flush=True,
    )
    training_args = transformers.TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=float(training["num_train_epochs"]),
        learning_rate=float(training["learning_rate"]),
        weight_decay=float(training["weight_decay"]),
        warmup_ratio=float(training["warmup_ratio"]),
        per_device_train_batch_size=int(
            training["per_device_train_batch_size"]
        ),
        gradient_accumulation_steps=int(
            training["gradient_accumulation_steps"]
        ),
        logging_steps=int(training["logging_steps"]),
        save_strategy="no",
        eval_strategy="no",
        bf16=True,
        fp16=False,
        gradient_checkpointing=True,
        report_to=[],
        seed=int(config["seed"]),
        data_seed=int(config["seed"]),
        remove_unused_columns=True,
    )
    trainer = transformers.Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        data_collator=transformers.DataCollatorWithPadding(
            tokenizer=tokenizer,
            pad_to_multiple_of=8,
        ),
    )
    result = trainer.train()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    report = {
        "status": "ok",
        "model_family": "encoder_sequence_classifier",
        "model": "microsoft/codebert-base",
        "readout_type": "roberta_cls_classification_head",
        "pooling_mechanism": "first_token_cls_representation",
        "training_objective": "binary_side_choice_cross_entropy",
        "supports_abstention": False,
        "seed": int(config["seed"]),
        "max_seq_length": int(config["max_seq_length"]),
        "training_examples": len(train_rows),
        "training_metrics": result.metrics,
        "checkpoint": config["output_dir"],
        "claim_boundary": (
            "Architecture control trained on the same 6,000 bidirectional "
            "PrimeVul side-choice rows. It does not share Qwen's earlier "
            "pair-diff initialization."
        ),
    }
    write_json(ROOT / config["report_output"], report)
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
