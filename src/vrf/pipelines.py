from __future__ import annotations

from typing import Any

from vrf.inference import build_backend, run_generation
from vrf.io_utils import read_json, read_jsonl, write_jsonl
from vrf.schemas import ExperimentRecord, SecureCodeSample
from vrf.tracking import log_experiment


def run_baseline(config_path: str) -> dict[str, Any]:
    config = read_json(config_path)
    samples = [SecureCodeSample.from_dict(row) for row in read_jsonl(config["dataset_path"])]
    backend = build_backend(config["backend"])
    generations = [run_generation(backend, sample) for sample in samples]
    write_jsonl(config["output_path"], [generation.to_dict() for generation in generations])

    metrics = {
        "num_examples": len(generations),
        "avg_latency_ms": round(sum(item.latency_ms for item in generations) / max(1, len(generations)), 4),
        "label_accuracy": round(sum(1 for item in generations if item.label_correct) / max(1, len(generations)), 4),
    }
    tracker_path = config.get("tracker_path")
    if tracker_path:
        log_experiment(
            ExperimentRecord(
                stage="baseline",
                model_name=backend.model_version,
                config_path=config_path,
                artifact_path=config["output_path"],
                metrics=metrics,
            ),
            tracker_path,
        )
    return metrics
