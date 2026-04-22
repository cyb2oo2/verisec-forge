from __future__ import annotations

from pathlib import Path
from typing import Any

from vrf.io_utils import read_json, read_jsonl
from vrf.schemas import ExperimentRecord
from vrf.tracking import log_experiment


def optional_import_train_stack() -> dict[str, Any]:
    try:
        import datasets
        import torch
        import transformers
        import trl
    except ImportError as exc:
        raise RuntimeError(
            "Training dependencies are missing. Install with `python -m pip install -e .[train]`."
        ) from exc
    return {
        "datasets": datasets,
        "torch": torch,
        "transformers": transformers,
        "trl": trl,
    }


def load_config(config_path: str) -> dict[str, Any]:
    return read_json(config_path)


def load_dataset(path: str) -> list[dict[str, Any]]:
    return read_jsonl(path)


def ensure_output_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def resolve_local_model_source(model_name: str, local_files_only: bool) -> str:
    if not local_files_only:
        return model_name
    model_path = Path(model_name)
    if model_path.exists():
        return model_name
    try:
        from huggingface_hub import snapshot_download

        return snapshot_download(model_name, local_files_only=True)
    except Exception:
        return model_name


def pretrained_kwargs(local_files_only: bool) -> dict[str, Any]:
    if local_files_only:
        return {"local_files_only": True}
    return {}


def load_tokenizer(
    *,
    transformers_module: Any,
    model_name: str,
    local_files_only: bool = False,
) -> Any:
    model_source = resolve_local_model_source(model_name, local_files_only)
    tokenizer = transformers_module.AutoTokenizer.from_pretrained(
        model_source,
        **pretrained_kwargs(local_files_only),
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def render_instruction_prompt(
    *,
    tokenizer: Any,
    prompt: str,
    system_prompt: str = "",
    add_generation_prompt: bool = True,
    response_prefix: str | None = None,
) -> str:
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    if getattr(tokenizer, "chat_template", None):
        rendered = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=add_generation_prompt,
        )
    elif system_prompt:
        rendered = f"{system_prompt}\n\n{prompt}"
    else:
        rendered = prompt
    if response_prefix:
        rendered += response_prefix
    return rendered


def record_training_stage(config_path: str, config: dict[str, Any], metrics: dict[str, Any]) -> None:
    tracker_path = config.get("tracker_path")
    if tracker_path:
        log_experiment(
            ExperimentRecord(
                stage=config["stage"],
                model_name=config["model_name"],
                config_path=config_path,
                artifact_path=config["output_dir"],
                metrics=metrics,
            ),
            tracker_path,
        )


def cpu_training_overrides(torch_module: Any) -> dict[str, Any]:
    if getattr(torch_module, "cuda", None) and torch_module.cuda.is_available():
        return {
            "fp16": True,
            "bf16": False,
        }
    return {
        "use_cpu": True,
        "bf16": False,
        "fp16": False,
    }
