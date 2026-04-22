from __future__ import annotations

from vrf.training_common import (
    cpu_training_overrides,
    ensure_output_dir,
    load_config,
    load_dataset,
    load_tokenizer,
    optional_import_train_stack,
    pretrained_kwargs,
    record_training_stage,
    resolve_local_model_source,
)


def run_reward_model(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    ensure_output_dir(config["output_dir"])
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]

    rows = load_dataset(config["dataset_path"])
    dataset = datasets.Dataset.from_list(
        [{"text": f"{row['prompt']}\n{row['response']}", "label": float(row["score"])} for row in rows]
    )

    local_files_only = bool(config.get("local_files_only"))
    tokenizer = load_tokenizer(
        transformers_module=transformers,
        model_name=config["model_name"],
        local_files_only=local_files_only,
    )
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        resolve_local_model_source(config["model_name"], local_files_only),
        num_labels=1,
        ignore_mismatched_sizes=True,
        **pretrained_kwargs(local_files_only),
    )

    def preprocess(batch: dict[str, list[object]]) -> dict[str, object]:
        tokenized = tokenizer(batch["text"], truncation=True, max_length=config["training_args"]["max_length"])
        tokenized["labels"] = batch["label"]
        return tokenized

    dataset = dataset.map(preprocess, batched=True)
    args = transformers.TrainingArguments(
        output_dir=config["output_dir"],
        num_train_epochs=config["training_args"]["num_train_epochs"],
        learning_rate=config["training_args"]["learning_rate"],
        per_device_train_batch_size=config["training_args"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training_args"]["gradient_accumulation_steps"],
        logging_steps=config["training_args"]["logging_steps"],
        save_steps=config["training_args"]["save_steps"],
        report_to=[],
        **cpu_training_overrides(torch),
    )
    trainer = transformers.Trainer(model=model, args=args, train_dataset=dataset, processing_class=tokenizer)
    trainer.train()
    trainer.save_model(config["output_dir"])
    tokenizer.save_pretrained(config["output_dir"])

    metrics = {"train_rows": len(rows), "output_dir": config["output_dir"]}
    record_training_stage(config_path, config, metrics)
    return metrics
