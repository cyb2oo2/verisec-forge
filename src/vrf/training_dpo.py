from __future__ import annotations

from pathlib import Path

from vrf.training_common import (
    cpu_training_overrides,
    ensure_output_dir,
    load_config,
    load_dataset,
    load_tokenizer,
    optional_import_train_stack,
    pretrained_kwargs,
    record_training_stage,
    render_instruction_prompt,
    resolve_local_model_source,
)


def run_dpo(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    ensure_output_dir(config["output_dir"])
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    trl = stack["trl"]

    tokenizer_source = config.get("tokenizer_name") or config["model_name"]
    local_files_only = bool(config.get("local_files_only"))
    tokenizer = load_tokenizer(
        transformers_module=transformers,
        model_name=tokenizer_source,
        local_files_only=local_files_only,
    )

    system_prompt = config.get("system_prompt", "")

    def format_prompt(prompt: str) -> str:
        return render_instruction_prompt(
            tokenizer=tokenizer,
            prompt=prompt,
            system_prompt=system_prompt,
            add_generation_prompt=True,
        )

    rows = load_dataset(config["preference_dataset_path"])
    dataset = datasets.Dataset.from_list(
        [{"prompt": format_prompt(row["prompt"]), "chosen": row["chosen"], "rejected": row["rejected"]} for row in rows]
    )

    training_mode = config.get("training_mode", "full_model")

    def load_causal_model(model_name: str, *, trainable: bool):
        model_source = resolve_local_model_source(model_name, local_files_only)
        adapter_config_path = Path(model_name) / "adapter_config.json"
        if adapter_config_path.exists():
            try:
                from peft import AutoPeftModelForCausalLM
            except ImportError as exc:
                raise RuntimeError("peft is required to load LoRA checkpoints for DPO") from exc
            if training_mode == "adapter_only":
                peft_model = AutoPeftModelForCausalLM.from_pretrained(
                    model_source,
                    is_trainable=trainable,
                    **pretrained_kwargs(local_files_only),
                )
                if trainable:
                    return peft_model
                merged_model = peft_model.merge_and_unload()
                for parameter in merged_model.parameters():
                    parameter.requires_grad = False
                return merged_model

            model = AutoPeftModelForCausalLM.from_pretrained(model_source, **pretrained_kwargs(local_files_only))
            merged_model = model.merge_and_unload()
            # `merge_and_unload()` returns a frozen base model. Full-model DPO
            # needs trainable parameters, otherwise checkpoints get saved without
            # any updates.
            for parameter in merged_model.parameters():
                parameter.requires_grad = trainable
            return merged_model
        model = transformers.AutoModelForCausalLM.from_pretrained(model_source, **pretrained_kwargs(local_files_only))
        for parameter in model.parameters():
            parameter.requires_grad = trainable
        return model

    model = load_causal_model(config["model_name"], trainable=True)
    ref_model = load_causal_model(config["reference_model_name"], trainable=False)

    args = trl.DPOConfig(
        output_dir=config["output_dir"],
        num_train_epochs=config["training_args"]["num_train_epochs"],
        learning_rate=config["training_args"]["learning_rate"],
        per_device_train_batch_size=config["training_args"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training_args"]["gradient_accumulation_steps"],
        logging_steps=config["training_args"]["logging_steps"],
        save_steps=config["training_args"]["save_steps"],
        max_length=config["training_args"]["max_length"],
        beta=config["training_args"]["beta"],
        report_to=[],
        **cpu_training_overrides(torch),
    )
    trainer = trl.DPOTrainer(
        model=model,
        ref_model=ref_model,
        args=args,
        train_dataset=dataset,
        processing_class=tokenizer,
    )
    trainer.train()
    trainer.save_model(config["output_dir"])
    tokenizer.save_pretrained(config["output_dir"])

    metrics = {"train_rows": len(rows), "output_dir": config["output_dir"]}
    record_training_stage(config_path, config, metrics)
    return metrics
