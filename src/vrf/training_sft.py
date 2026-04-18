from __future__ import annotations

import json

from vrf.training_common import cpu_training_overrides, ensure_output_dir, load_config, load_dataset, optional_import_train_stack, record_training_stage


def run_sft(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    ensure_output_dir(config["output_dir"])
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    trl = stack["trl"]

    rows = load_dataset(config["train_dataset_path"])
    pretrained_kwargs: dict[str, object] = {}
    if config.get("local_files_only"):
        pretrained_kwargs["local_files_only"] = True
    tokenizer = transformers.AutoTokenizer.from_pretrained(config["model_name"], **pretrained_kwargs)
    model = transformers.AutoModelForCausalLM.from_pretrained(config["model_name"], **pretrained_kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    system_prompt = config.get("system_prompt", "")
    response_field = config.get("response_field", "response")

    has_chat_template = bool(getattr(tokenizer, "chat_template", None))

    def format_example(row: dict[str, object]) -> dict[str, object]:
        assistant_content = str(row[response_field])
        if config.get("response_format") == "structured_json" and not assistant_content.strip().startswith("{"):
            assistant_content = json.dumps(
                {
                    "reasoning": str(row.get("reasoning", "")),
                    "final_answer": str(row.get("gold_answer", "")),
                },
                ensure_ascii=False,
            )
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": str(row["prompt"])})
        messages.append({"role": "assistant", "content": assistant_content})
        if has_chat_template:
            return {
                "prompt": messages[:-1],
                "completion": [messages[-1]],
            }

        prompt_parts = []
        if system_prompt:
            prompt_parts.append(system_prompt)
        prompt_parts.append(str(row["prompt"]))
        prompt_text = "\n\n".join(prompt_parts)
        return {
            "prompt": prompt_text,
            "completion": assistant_content,
        }

    dataset = datasets.Dataset.from_list([format_example(row) for row in rows])

    peft_cfg = config.get("peft", {})
    peft_config = None
    if peft_cfg.get("enabled"):
        try:
            from peft import LoraConfig
        except ImportError as exc:
            raise RuntimeError("peft is required for PEFT-based SFT runs") from exc
        peft_config = LoraConfig(
            r=peft_cfg["r"],
            lora_alpha=peft_cfg["lora_alpha"],
            lora_dropout=peft_cfg["lora_dropout"],
            target_modules=peft_cfg["target_modules"],
            bias="none",
            task_type="CAUSAL_LM",
        )

    args = trl.SFTConfig(
        output_dir=config["output_dir"],
        num_train_epochs=config["training_args"]["num_train_epochs"],
        learning_rate=config["training_args"]["learning_rate"],
        per_device_train_batch_size=config["training_args"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training_args"]["gradient_accumulation_steps"],
        logging_steps=config["training_args"]["logging_steps"],
        save_steps=config["training_args"]["save_steps"],
        max_length=config["training_args"]["max_seq_length"],
        assistant_only_loss=False,
        completion_only_loss=True,
        report_to=[],
        **cpu_training_overrides(torch),
    )
    trainer = trl.SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=args,
        peft_config=peft_config,
    )
    trainer.train()
    trainer.save_model(config["output_dir"])
    tokenizer.save_pretrained(config["output_dir"])

    metrics = {"train_rows": len(rows), "output_dir": config["output_dir"]}
    record_training_stage(config_path, config, metrics)
    return metrics
