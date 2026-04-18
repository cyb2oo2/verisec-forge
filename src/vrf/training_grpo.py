from __future__ import annotations

from pathlib import Path
from typing import Any

from vrf.text_utils import extract_numeric_answer, length_penalty, parse_reasoning_and_answer, parse_structured_response
from vrf.training_common import cpu_training_overrides, ensure_output_dir, load_config, load_dataset, optional_import_train_stack, record_training_stage


def reward_fn(
    completions: list[str],
    gold_answers: list[str],
    reward_config: dict[str, Any],
    response_prefix: str | None = None,
) -> list[float]:
    rewards: list[float] = []
    for completion, gold_answer in zip(completions, gold_answers, strict=False):
        completion_text = f"{response_prefix}{completion}" if response_prefix else completion
        reasoning, final_answer, format_ok, _ = parse_structured_response(completion_text)
        if not format_ok:
            reasoning, final_answer, format_ok = parse_reasoning_and_answer(completion_text)
        correctness = 1.0 if extract_numeric_answer(final_answer) == extract_numeric_answer(gold_answer) else 0.0
        format_component = 1.0 if format_ok else 0.0
        penalty = length_penalty(reasoning, reward_config["max_reasoning_tokens"])
        rewards.append(
            reward_config["correctness_weight"] * correctness
            + reward_config["format_weight"] * format_component
            - reward_config["length_penalty_weight"] * penalty
        )
    return rewards


def run_grpo(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    ensure_output_dir(config["output_dir"])
    stack = optional_import_train_stack()
    datasets = stack["datasets"]
    torch = stack["torch"]
    transformers = stack["transformers"]
    trl = stack["trl"]

    tokenizer_source = config.get("tokenizer_name") or config["model_name"]
    tokenizer = transformers.AutoTokenizer.from_pretrained(tokenizer_source)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    system_prompt = config.get("system_prompt", "")

    def format_prompt(prompt: str) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        if getattr(tokenizer, "chat_template", None):
            rendered = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        elif system_prompt:
            rendered = f"{system_prompt}\n\n{prompt}"
        else:
            rendered = prompt
        response_prefix = config.get("response_prefix")
        if response_prefix:
            rendered += response_prefix
        return rendered

    rows = load_dataset(config["train_dataset_path"])
    dataset = datasets.Dataset.from_list([{"prompt": format_prompt(row["prompt"]), "gold_answer": row["gold_answer"]} for row in rows])

    def load_causal_model(model_name: str):
        adapter_config_path = Path(model_name) / "adapter_config.json"
        if adapter_config_path.exists():
            try:
                from peft import AutoPeftModelForCausalLM
            except ImportError as exc:
                raise RuntimeError("peft is required to load LoRA checkpoints for GRPO") from exc
            model = AutoPeftModelForCausalLM.from_pretrained(model_name)
            return model.merge_and_unload()
        return transformers.AutoModelForCausalLM.from_pretrained(model_name)

    model = load_causal_model(config["model_name"])

    def reward_wrapper(prompts: list[str], completions: list[str], gold_answer: list[str], **_: Any) -> list[float]:
        return reward_fn(
            completions,
            gold_answer,
            config["reward"],
            response_prefix=config.get("response_prefix"),
        )

    args = trl.GRPOConfig(
        output_dir=config["output_dir"],
        num_train_epochs=config["training_args"]["num_train_epochs"],
        max_steps=config["training_args"].get("max_steps", -1),
        learning_rate=config["training_args"]["learning_rate"],
        per_device_train_batch_size=config["training_args"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training_args"]["gradient_accumulation_steps"],
        logging_steps=config["training_args"]["logging_steps"],
        save_steps=config["training_args"]["save_steps"],
        max_completion_length=config["training_args"]["max_completion_length"],
        num_generations=config["training_args"].get("num_generations", config["training_args"]["per_device_train_batch_size"]),
        generation_batch_size=config["training_args"].get("generation_batch_size"),
        steps_per_generation=config["training_args"].get("steps_per_generation"),
        report_to=[],
        **cpu_training_overrides(torch),
    )
    trainer = trl.GRPOTrainer(
        model=model,
        reward_funcs=reward_wrapper,
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
