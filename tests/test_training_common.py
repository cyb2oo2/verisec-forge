from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from vrf.training_common import cpu_training_overrides, load_config, load_dataset, resolve_local_model_source


def test_load_config_and_dataset_round_trip() -> None:
    tmp_path = Path(".tmp_test_runs") / f"training-common-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    config_path = tmp_path / "config.json"
    dataset_path = tmp_path / "dataset.jsonl"

    config_payload = {"model_name": "demo-model", "output_dir": "checkpoints/demo"}
    config_path.write_text(json.dumps(config_payload), encoding="utf-8")
    dataset_path.write_text(
        "\n".join(
            [
                json.dumps({"id": "row-1", "prompt": "a"}),
                json.dumps({"id": "row-2", "prompt": "b"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert load_config(str(config_path)) == config_payload
    assert load_dataset(str(dataset_path)) == [
        {"id": "row-1", "prompt": "a"},
        {"id": "row-2", "prompt": "b"},
    ]


def test_resolve_local_model_source_prefers_existing_path() -> None:
    tmp_path = Path(".tmp_test_runs") / f"model-source-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    assert resolve_local_model_source(str(tmp_path), True) == str(tmp_path)
    assert resolve_local_model_source("remote/model", False) == "remote/model"


def test_cpu_training_overrides_cover_cpu_and_cuda_paths() -> None:
    cpu_torch = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False))
    gpu_torch = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: True), float16="float16")

    assert cpu_training_overrides(cpu_torch) == {"use_cpu": True, "bf16": False, "fp16": False}
    assert cpu_training_overrides(gpu_torch) == {"fp16": True, "bf16": False}
