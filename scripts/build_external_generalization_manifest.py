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

from vrf.reproducibility import count_jsonl_rows, sha256_file


ARTIFACTS: list[tuple[str, str, str]] = [
    (
        "primevul_time_train_metadata",
        "data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl",
        "PrimeVul <=2020 paired-diff training metadata used by time-disjoint and learned-router experiments.",
    ),
    (
        "primevul_time_eval_metadata",
        "data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl",
        "PrimeVul >=2021 paired-diff eval metadata.",
    ),
    (
        "deltasecommits_train_metadata",
        "data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl",
        "DeltaSecommits C/C++ paired-diff train metadata.",
    ),
    (
        "deltasecommits_eval_metadata",
        "data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl",
        "DeltaSecommits C/C++ paired-diff eval metadata.",
    ),
    (
        "patcheval_train_metadata",
        "data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl",
        "PatchEval paired-diff train metadata.",
    ),
    (
        "patcheval_eval_metadata",
        "data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
        "PatchEval paired-diff eval metadata.",
    ),
    (
        "matched_mixed_train_metadata",
        "data/processed/secure_code_matched_mixed_primevul_time_short_deltasecommits_pair_diff_train_metadata.jsonl",
        "Matched short PrimeVul-time + DeltaSecommits mixed-source training metadata.",
    ),
    (
        "primevul_time_direct_predictions",
        "outputs/secure_code_primevul_time_disjoint_pair_coupled_direct_train_v1_predictions.jsonl",
        "PrimeVul <=2020 direct-train expert predictions on later-CVE eval.",
    ),
    (
        "primevul_time_matched_mixed_predictions",
        "outputs/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_pair_coupled_v1_predictions.jsonl",
        "Matched mixed-source checkpoint predictions on PrimeVul later-CVE eval.",
    ),
    (
        "deltasecommits_expert_predictions",
        "outputs/secure_code_deltasecommits_cls_qwen15bcoder_lora_pair_diff_cpp_v1_eval_predictions.jsonl",
        "DeltaSecommits source expert predictions on Delta eval.",
    ),
    (
        "deltasecommits_matched_mixed_predictions",
        "outputs/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_delta_eval_predictions.jsonl",
        "Matched mixed-source checkpoint predictions on Delta eval.",
    ),
    (
        "deltasecommits_primevul_checkpoint_predictions",
        "outputs/secure_code_deltasecommits_primevul_time_checkpoint_zero_shot_predictions.jsonl",
        "PrimeVul checkpoint zero-shot predictions on DeltaSecommits rows for learned routed-system cross-route evaluation.",
    ),
    (
        "deltasecommits_on_primevul_predictions",
        "outputs/secure_code_deltasecommits_adapter_primevul_time_eval_predictions.jsonl",
        "DeltaSecommits source expert cross-source predictions on PrimeVul later-CVE eval.",
    ),
    (
        "deltasecommits_on_patcheval_predictions",
        "outputs/secure_code_deltasecommits_adapter_patcheval_eval_predictions.jsonl",
        "DeltaSecommits source expert cross-source predictions on PatchEval eval.",
    ),
    (
        "patcheval_matched_mixed_raw_predictions",
        "outputs/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_patcheval_raw_predictions.jsonl",
        "Matched mixed-source checkpoint raw predictions on PatchEval eval used as fallback rows in learned routed-system evaluation.",
    ),
    (
        "patcheval_seed42_predictions",
        "outputs/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_v1_eval_predictions.jsonl",
        "PatchEval seed42 source expert predictions on PatchEval eval.",
    ),
    (
        "patcheval_seed7_predictions",
        "outputs/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_seed7_v1_eval_predictions.jsonl",
        "PatchEval seed7 source expert predictions on PatchEval eval.",
    ),
    (
        "patcheval_seed99_predictions",
        "outputs/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_seed99_v1_eval_predictions.jsonl",
        "PatchEval seed99 source expert predictions on PatchEval eval.",
    ),
    (
        "patcheval_on_primevul_predictions",
        "outputs/secure_code_patcheval_adapter_primevul_time_eval_predictions.jsonl",
        "PatchEval source expert reverse-transfer predictions on PrimeVul later-CVE eval.",
    ),
    (
        "patcheval_on_delta_predictions",
        "outputs/secure_code_patcheval_adapter_delta_eval_predictions.jsonl",
        "PatchEval source expert reverse-transfer predictions on Delta eval.",
    ),
    (
        "primevul_time_on_patcheval_predictions",
        "outputs/secure_code_primevul_time_adapter_patcheval_eval_predictions.jsonl",
        "PrimeVul-time source expert cross-source predictions on PatchEval eval.",
    ),
]

GENERATED_ARTIFACTS: list[tuple[str, str, str]] = [
    ("time_disjoint_direct_report", "reports/secure_code_primevul_time_disjoint_direct_train_v1.json", "PrimeVul time-disjoint direct-train pair-coupled report."),
    ("deltasecommits_delta_only_report", "reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json", "Delta-only expert pair-coupled report."),
    ("patcheval_zero_shot_report", "reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json", "PatchEval matched-mixed zero-shot report."),
    ("patcheval_multiseed_report", "reports/secure_code_patcheval_adapter_multiseed_v1.json", "PatchEval source expert multi-seed report."),
    ("patcheval_cross_source_report", "reports/secure_code_patcheval_cross_source_specialization_v1.json", "PatchEval reverse cross-source specialization report."),
    ("deltasecommits_on_primevul_eval_report", "reports/secure_code_deltasecommits_adapter_primevul_time_eval_report.json", "DeltaSecommits source expert default-threshold report on PrimeVul later-CVE eval."),
    ("deltasecommits_on_patcheval_eval_report", "reports/secure_code_deltasecommits_adapter_patcheval_eval_report.json", "DeltaSecommits source expert default-threshold report on PatchEval eval."),
    ("primevul_time_on_patcheval_eval_report", "reports/secure_code_primevul_time_adapter_patcheval_eval_report.json", "PrimeVul-time source expert default-threshold report on PatchEval eval."),
    ("three_source_mixture_report", "reports/secure_code_three_source_adapter_mixture_v1.json", "Three-source source-routed adapter mixture report."),
    ("non_oracle_source_router_report", "reports/secure_code_non_oracle_source_router_v1.json", "Metadata-schema source router report."),
    ("content_source_router_report", "reports/secure_code_content_source_router_v1.json", "Surface/diff-body content router stress report."),
    ("learned_content_source_router_report", "reports/secure_code_learned_content_source_router_v1.json", "Learned character n-gram source router report."),
    ("learned_content_routed_system_report", "reports/secure_code_learned_content_routed_system_v1.json", "Learned diff-body content router evaluated as an end-to-end routed system with explicit fallback accounting."),
]


def artifact_entry(role: str, path: str, note: str) -> dict[str, Any]:
    full_path = ROOT / path
    if not full_path.exists():
        raise FileNotFoundError(path)
    entry: dict[str, Any] = {
        "role": role,
        "path": path,
        "sha256": sha256_file(full_path),
        "bytes": full_path.stat().st_size,
        "note": note,
    }
    if full_path.suffix == ".jsonl":
        entry["rows"] = count_jsonl_rows(full_path)
    return entry


def build_manifest() -> dict[str, Any]:
    return {
        "name": "external_generalization_and_source_routing_v1",
        "description": (
            "Manifest-backed local artifacts for DeltaSecommits/PatchEval/time-disjoint external-generalization, "
            "source-aware adapter mixture, and source-router reports."
        ),
        "created_utc": "2026-05-20",
        "command": [
            ".venv/Scripts/python.exe",
            "scripts/build_reproducibility_bundle.py",
            "--manifest",
            "reproducibility/external_generalization_manifest.json",
            "--check-only",
            "--include-generated",
        ],
        "artifacts": [artifact_entry(role, path, note) for role, path, note in ARTIFACTS],
        "generated_artifacts": [artifact_entry(role, path, note) for role, path, note in GENERATED_ARTIFACTS],
        "expected": {
            "three_source_single_matched_mixed_ba": 0.8591,
            "three_source_source_routed_ba": 0.8664,
            "patcheval_adapter_multiseed_pair_coupled_ba_mean": 0.8172,
            "patcheval_reverse_primevul_pair_coupled_ba": 0.8521,
            "patcheval_reverse_delta_pair_coupled_ba": 0.8440,
            "learned_diff_body_router_row_accuracy": 0.9063,
            "learned_diff_body_router_pair_group_accuracy": 0.9057,
            "learned_content_routed_system_ba": 0.8664,
            "learned_content_routed_system_group_all_correct": 0.8548,
            "learned_content_routed_system_fallback_rows": 0,
        },
        "limitations": [
            "This manifest makes external-generalization and source-routing local artifacts auditable by path, byte size, row count, and SHA256.",
            "It does not include model checkpoints; reports can be audited from materialized predictions and metadata.",
            "It is manifest-backed reproducibility, not yet a public fresh-clone bundle unless packaged and uploaded with the bundle workflow.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build external-generalization reproducibility manifest.")
    parser.add_argument("--output", default="reproducibility/external_generalization_manifest.json")
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_manifest(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
