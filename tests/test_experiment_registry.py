from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "experiments/registry.json"


def load_registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_experiment_registry_schema_and_paths() -> None:
    registry = load_registry()
    allowed_layers = set(registry["layer_order"])
    allowed_reproducibility = set(registry["reproducibility_levels"])
    seen_ids: set[str] = set()

    assert registry["schema_version"] == 1
    assert registry["experiments"]

    for item in registry["experiments"]:
        assert item["id"] not in seen_ids
        seen_ids.add(item["id"])
        assert item["status"] == "retained"
        assert item["layer"] in allowed_layers
        assert item["reproducibility"] in allowed_reproducibility
        assert item["claim"].strip(), item["id"]
        assert item["boundary"].strip(), item["id"]

        primary = ROOT / item["primary_report"]
        assert primary.exists(), item["primary_report"]

        for relative_path in item.get("supporting_artifacts", []):
            assert (ROOT / relative_path).exists(), relative_path


def test_experiment_registry_covers_public_system_reports() -> None:
    registry = load_registry()
    registered_paths = {
        item["primary_report"] for item in registry["experiments"]
    } | {
        path
        for item in registry["experiments"]
        for path in item.get("supporting_artifacts", [])
    }

    required_paths = {
        "reports/RELATIONAL_BENCHMARK_V2.md",
        "reports/VERIPATCH_RR_QWEN15B_SMOKE.md",
        "reports/CROSS_MODEL_RELATIONAL_AUDIT.md",
        "reports/CROSS_MODEL_REPLICATION.md",
        "reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md",
        "reports/READOUT_ABLATION.md",
        "reports/READOUT_CONFIRMATORY.md",
        "reports/FROZEN_BACKBONE_READOUT_CONTROL.md",
        "docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md",
        "docs/CI_TESTING_STRATEGY.md",
        "reproducibility/veripatch_external_smoke_manifest.json",
    }

    assert required_paths <= registered_paths


def test_experiment_matrix_is_generated_from_registry() -> None:
    matrix = (ROOT / "reports/EXPERIMENT_MATRIX.md").read_text(encoding="utf-8")
    assert "](..\\reports\\" not in matrix
    assert "](..\\docs\\" not in matrix

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_experiment_matrix.py",
            "--check-only",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
