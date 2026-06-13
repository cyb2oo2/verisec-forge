from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_json
from vrf.reproducibility import count_jsonl_rows, sha256_file


def artifact_entry(role: str, path: str) -> dict[str, Any]:
    full_path = ROOT / path
    if not full_path.exists():
        raise FileNotFoundError(path)
    entry: dict[str, Any] = {
        "role": role,
        "path": path,
        "sha256": sha256_file(full_path),
        "bytes": full_path.stat().st_size,
    }
    if full_path.suffix == ".jsonl":
        entry["rows"] = count_jsonl_rows(full_path)
    return entry


def build_manifest() -> dict[str, Any]:
    report_path = "reports/secure_code_readout_confirmatory_v1.json"
    report = read_json(ROOT / report_path)
    artifacts = [
        artifact_entry(
            "confirmatory_benchmark",
            "data/processed/secure_code_readout_confirmatory_v1.jsonl",
        ),
        artifact_entry(
            "confirmatory_runtime_512",
            "data/processed/"
            "secure_code_readout_confirmatory_v1_runtime512.jsonl",
        ),
    ]
    generated = [
        artifact_entry(
            "dataset_summary",
            "reports/secure_code_readout_confirmatory_dataset_v1.json",
        ),
        artifact_entry(
            "runtime_summary",
            "reports/"
            "secure_code_readout_confirmatory_runtime512_summary_v1.json",
        ),
        artifact_entry("confirmatory_report_json", report_path),
        artifact_entry(
            "confirmatory_report_markdown",
            "reports/READOUT_CONFIRMATORY.md",
        ),
    ]
    for readout in ("terminal", "mean", "changed_hunk"):
        for seed in (7, 123):
            artifacts.append(
                artifact_entry(
                    f"{readout}_seed{seed}_predictions",
                    "outputs/secure_code_readout_confirmatory_"
                    f"{readout}_seed{seed}_predictions.jsonl",
                )
            )
            generated.append(
                artifact_entry(
                    f"{readout}_seed{seed}_training_report",
                    "reports/secure_code_readout_confirmatory_qwen15b_"
                    f"{readout}_seed{seed}_training_report.json",
                )
            )
    expected = {}
    for candidate, comparison in report[
        "paired_comparisons_vs_terminal"
    ].items():
        pooled = comparison["pooled_pair_cluster"]
        expected[candidate] = {
            "canonical_accuracy_delta": pooled[
                "canonical_accuracy_delta"
            ],
            "macro_suffix_consistency_delta": pooled[
                "macro_suffix_consistency_delta"
            ],
            "success_rule": comparison["success_rule"],
        }
    return {
        "name": "independent_readout_confirmatory_v1",
        "description": (
            "Independent new-pair, new-suffix, two-seed confirmation of "
            "terminal, mean, and changed-hunk Qwen readouts."
        ),
        "created_utc": "2026-06-13",
        "analysis_command": [
            ".venv/Scripts/python.exe",
            "scripts/analyze_readout_confirmatory.py",
        ],
        "validation_command": [
            ".venv/Scripts/python.exe",
            "scripts/build_reproducibility_bundle.py",
            "--manifest",
            "reproducibility/readout_confirmatory_manifest.json",
            "--check-only",
            "--include-generated",
        ],
        "artifacts": artifacts,
        "generated_artifacts": generated,
        "expected": expected,
        "limitations": [
            "The manifest reproduces analysis from stored predictions, not GPU training.",
            "Model checkpoints are local and are not included in Git or this manifest.",
            "This confirms readout-conditioned training behavior; a frozen-backbone pooling control remains future work.",
            "Endpoint robustness and side-order equivariance are separate capabilities.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the readout confirmation artifact manifest."
    )
    parser.add_argument(
        "--output",
        default="reproducibility/readout_confirmatory_manifest.json",
    )
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_manifest(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
