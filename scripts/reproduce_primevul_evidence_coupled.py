from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_json, read_jsonl


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def row_count(path: Path) -> int | None:
    return len(read_jsonl(path)) if path.suffix == ".jsonl" else None


def validate_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    path = REPO_ROOT / artifact["path"]
    result: dict[str, Any] = {
        "role": artifact["role"],
        "path": artifact["path"],
        "exists": path.exists(),
    }
    if not path.exists():
        result["status"] = "missing"
        return result
    actual_bytes = path.stat().st_size
    actual_sha256 = sha256_file(path)
    actual_rows = row_count(path)
    rows_match = True if "rows" not in artifact else actual_rows == int(artifact["rows"])
    result.update(
        {
            "expected_bytes": artifact["bytes"],
            "actual_bytes": actual_bytes,
            "expected_rows": artifact.get("rows"),
            "actual_rows": actual_rows,
            "expected_sha256": artifact["sha256"],
            "actual_sha256": actual_sha256,
            "status": "ok"
            if (
                actual_bytes == int(artifact["bytes"])
                and rows_match
                and actual_sha256.lower() == str(artifact["sha256"]).lower()
            )
            else "mismatch",
        }
    )
    return result


def validate_many(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [validate_artifact(artifact) for artifact in artifacts]


def run_command(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    return {
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def commands() -> list[list[str]]:
    py = sys.executable
    return [
        [
            py,
            "scripts/train_primevul_hunk_linear_scorer.py",
            "--train",
            "data/processed/primevul_candidate_recall_train_v1/hunk_plus_window_candidates.jsonl",
            "--eval",
            "data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl",
            "--k-values",
            "1,2,3,5,8",
            "--epochs",
            "60",
            "--learning-rate",
            "0.02",
            "--l2",
            "0.0001",
            "--seed",
            "42",
            "--json-output",
            "reports/secure_code_primevul_hunk_plus_window_linear_scorer_v1.json",
            "--md-output",
            "reports/PRIMEVUL_HUNK_PLUS_WINDOW_LINEAR_SCORER.md",
            "--scored-eval-output",
            "outputs/secure_code_primevul_hunk_plus_window_linear_scorer_eval_v1.jsonl",
        ],
        [
            py,
            "scripts/evaluate_primevul_predicted_side_hunk_scorer.py",
            "--candidates",
            "data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--scorer-report",
            "reports/secure_code_primevul_hunk_plus_window_linear_scorer_v1.json",
            "--k-values",
            "1,2,3,5,8",
            "--json-output",
            "reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json",
            "--md-output",
            "reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md",
            "--scored-output",
            "outputs/secure_code_primevul_predicted_side_hunk_scorer_eval_v1.jsonl",
        ],
        [
            py,
            "scripts/analyze_primevul_predicted_side_failures.py",
            "--scored-hunks",
            "outputs/secure_code_primevul_predicted_side_hunk_scorer_eval_v1.jsonl",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--top-n",
            "20",
            "--json-output",
            "reports/secure_code_primevul_predicted_side_failure_taxonomy_v1.json",
            "--md-output",
            "reports/PRIMEVUL_PREDICTED_SIDE_FAILURE_TAXONOMY.md",
        ],
        [
            py,
            "scripts/build_primevul_confident_side_inversion_set.py",
            "--dataset",
            "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--min-gap",
            "0.5",
            "--top-n",
            "20",
            "--output",
            "data/processed/secure_code_primevul_confident_side_inversions_gap50_v1.jsonl",
            "--summary-json",
            "reports/secure_code_primevul_confident_side_inversions_gap50_v1.json",
            "--summary-md",
            "reports/PRIMEVUL_CONFIDENT_SIDE_INVERSION_SET.md",
        ],
        [
            py,
            "scripts/evaluate_primevul_pair_side_correction.py",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--calibration-fraction",
            "0.3",
            "--seed",
            "42",
            "--epochs",
            "80",
            "--learning-rate",
            "0.05",
            "--l2",
            "0.0001",
            "--thresholds",
            "0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9",
            "--selector",
            "balanced_accuracy",
            "--json-output",
            "reports/secure_code_primevul_pair_side_correction_gate_v1.json",
            "--md-output",
            "reports/PRIMEVUL_PAIR_SIDE_CORRECTION_GATE.md",
            "--predictions-output",
            "outputs/secure_code_primevul_pair_side_correction_gate_v1_predictions.jsonl",
        ],
        [
            py,
            "scripts/analyze_primevul_pair_side_correction_multisplit.py",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--seeds",
            "7,13,42,99,123",
            "--calibration-fraction",
            "0.3",
            "--epochs",
            "80",
            "--learning-rate",
            "0.05",
            "--l2",
            "0.0001",
            "--thresholds",
            "0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9",
            "--selector",
            "balanced_accuracy",
            "--json-output",
            "reports/secure_code_primevul_pair_side_correction_multisplit_v1.json",
            "--md-output",
            "reports/PRIMEVUL_PAIR_SIDE_CORRECTION_MULTISPLIT.md",
        ],
        [
            py,
            "scripts/evaluate_primevul_contrastive_side_correction.py",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--hunk-candidates",
            "data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl",
            "--seeds",
            "7,13,42,99,123",
            "--calibration-fraction",
            "0.3",
            "--epochs",
            "80",
            "--learning-rate",
            "0.01",
            "--l2",
            "0.0001",
            "--thresholds",
            "0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9",
            "--selector",
            "balanced_accuracy",
            "--json-output",
            "reports/secure_code_primevul_contrastive_side_correction_v1.json",
            "--md-output",
            "reports/PRIMEVUL_CONTRASTIVE_SIDE_CORRECTION.md",
            "--predictions-output",
            "outputs/secure_code_primevul_contrastive_side_correction_seed42_v1_predictions.jsonl",
        ],
        [
            py,
            "scripts/build_primevul_paired_window_contrastive_dataset.py",
            "--predictions",
            "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
            "--hunk-candidates",
            "data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl",
            "--top-windows",
            "3",
            "--confident-gap",
            "0.5",
            "--jsonl-output",
            "data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl",
            "--summary-json",
            "reports/secure_code_primevul_paired_window_contrastive_eval_v1.json",
            "--summary-md",
            "reports/PRIMEVUL_PAIRED_WINDOW_CONTRASTIVE_DATASET.md",
        ],
        [
            py,
            "scripts/evaluate_primevul_paired_window_side_model.py",
            "--input",
            "data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl",
            "--seeds",
            "7,13,42,99,123",
            "--calibration-fraction",
            "0.3",
            "--epochs",
            "80",
            "--learning-rate",
            "0.01",
            "--l2",
            "0.0001",
            "--positive-weight",
            "8.0",
            "--thresholds",
            "0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9",
            "--selector",
            "balanced_accuracy",
            "--json-output",
            "reports/secure_code_primevul_paired_window_side_model_v1.json",
            "--md-output",
            "reports/PRIMEVUL_PAIRED_WINDOW_SIDE_MODEL.md",
        ],
    ]


def first_coverage(report: dict[str, Any], section: str, scorer: str) -> float:
    return report[section][scorer][0]["coverage"]


def metric_check(expected: dict[str, Any]) -> dict[str, Any]:
    hunk = read_json(REPO_ROOT / "reports/secure_code_primevul_hunk_plus_window_linear_scorer_v1.json")
    predicted = read_json(REPO_ROOT / "reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json")
    taxonomy = read_json(REPO_ROOT / "reports/secure_code_primevul_predicted_side_failure_taxonomy_v1.json")
    inversions = read_json(REPO_ROOT / "reports/secure_code_primevul_confident_side_inversions_gap50_v1.json")
    correction = read_json(REPO_ROOT / "reports/secure_code_primevul_pair_side_correction_gate_v1.json")
    correction_multisplit = read_json(REPO_ROOT / "reports/secure_code_primevul_pair_side_correction_multisplit_v1.json")
    contrastive = read_json(REPO_ROOT / "reports/secure_code_primevul_contrastive_side_correction_v1.json")
    paired_window = read_json(REPO_ROOT / "reports/secure_code_primevul_paired_window_contrastive_eval_v1.json")
    side_model = read_json(REPO_ROOT / "reports/secure_code_primevul_paired_window_side_model_v1.json")
    actual = {
        "hunk_linear_top1": first_coverage(hunk, "eval_coverage", "linear_scorer"),
        "hunk_side_aware_top1": first_coverage(hunk, "eval_coverage", "side_aware_linear_scorer"),
        "predicted_side_accuracy": predicted["side_source"]["pair_coupled_pred"]["decision_side_accuracy"],
        "oracle_matched_top1": first_coverage(predicted, "coverage", "oracle_side_aware_matched"),
        "predicted_side_top1": first_coverage(predicted, "coverage", "pair_coupled_predicted_side"),
        "side_correct_top1": first_coverage(predicted, "coverage", "pair_coupled_predicted_side_correct_only"),
        "side_wrong_top1": first_coverage(predicted, "coverage", "pair_coupled_predicted_side_wrong_only"),
        "side_wrong_rows": taxonomy["summary"]["wrong_sources"],
        "side_wrong_false_positives": taxonomy["summary"]["false_positives"],
        "side_wrong_false_negatives": taxonomy["summary"]["false_negatives"],
        "confident_inversion_rows": inversions["summary"]["rows"],
        "confident_inversion_pair_groups": inversions["summary"]["pair_groups"],
        "confident_inversion_false_positives": inversions["summary"]["false_positives"],
        "confident_inversion_false_negatives": inversions["summary"]["false_negatives"],
        "confident_inversion_avg_gap": inversions["summary"]["avg_gap"],
        "pair_side_correction_seed42_baseline_balanced_accuracy": correction["eval"]["baseline_pair_coupled"]["overall"]["balanced_accuracy"],
        "pair_side_correction_seed42_corrected_balanced_accuracy": correction["eval"]["corrected"]["overall"]["balanced_accuracy"],
        "pair_side_correction_seed42_gated_groups": correction["eval"]["corrected"]["gate_counts"]["gated_groups"],
        "pair_side_correction_multisplit_balanced_delta_mean": correction_multisplit["summary"]["balanced_accuracy_delta"]["mean"],
        "pair_side_correction_multisplit_group_delta_mean": correction_multisplit["summary"]["group_all_correct_delta"]["mean"],
        "contrastive_side_correction_seed42_corrected_balanced_accuracy": [
            row for row in contrastive["seed_reports"] if row["seed"] == 42
        ][0]["corrected_balanced_accuracy"],
        "contrastive_side_correction_multisplit_balanced_delta_mean": contrastive["summary"]["balanced_accuracy_delta"]["mean"],
        "contrastive_side_correction_multisplit_group_delta_mean": contrastive["summary"]["group_all_correct_delta"]["mean"],
        "paired_window_contrastive_rows": paired_window["summary"]["rows"],
        "paired_window_contrastive_label_b_rows": paired_window["summary"]["label_b_rows"],
        "paired_window_contrastive_high_gap_orientation_inversion_pairs": paired_window["summary"][
            "high_gap_orientation_inversion_pairs"
        ],
        "paired_window_contrastive_avg_prompt_chars": paired_window["summary"]["avg_prompt_chars"],
        "paired_window_side_model_balanced_accuracy_mean": side_model["summary"]["eval_balanced_accuracy"]["mean"],
        "paired_window_side_model_balanced_delta_mean": side_model["summary"]["balanced_accuracy_delta_vs_always_a"][
            "mean"
        ],
        "paired_window_side_model_label_b_recall_mean": side_model["summary"]["label_b_recall"]["mean"],
        "paired_window_side_model_top5_precision_mean": side_model["summary"]["eval_topk_precision"]["5"][
            "precision_mean"
        ],
        "paired_window_side_model_top10_precision_mean": side_model["summary"]["eval_topk_precision"]["10"][
            "precision_mean"
        ],
    }
    checks = {
        key: {
            "expected": expected[key],
            "actual": actual[key],
            "matches": actual[key] == expected[key],
        }
        for key in expected
    }
    return {"actual": actual, "checks": checks, "all_match": all(item["matches"] for item in checks.values())}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and reproduce the PrimeVul evidence-coupled reports.")
    parser.add_argument("--manifest", default="reproducibility/primevul_evidence_coupled_manifest.json")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    input_results = validate_many(manifest["artifacts"])
    missing_or_bad = [row for row in input_results if row["status"] != "ok"]
    if missing_or_bad:
        print(json.dumps({"status": "artifact_validation_failed", "artifacts": input_results}, indent=2))
        raise SystemExit(1)
    if args.check_only:
        print(json.dumps({"status": "ok", "artifacts": input_results}, indent=2))
        return

    command_results = [run_command(command) for command in commands()]
    generated_results = validate_many(manifest["generated_artifacts"])
    generated_bad = [row for row in generated_results if row["status"] != "ok"]
    checks = metric_check(manifest["expected"])
    status = "ok" if not generated_bad and checks["all_match"] else "reproduction_mismatch"
    print(
        json.dumps(
            {
                "status": status,
                "commands": command_results,
                "generated_artifacts": generated_results,
                "metric_check": checks,
            },
            indent=2,
        )
    )
    if status != "ok":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
