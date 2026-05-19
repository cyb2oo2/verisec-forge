from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def round4(value: float) -> float:
    return round(value, 4)


def pair_ba(report: dict[str, Any]) -> float:
    return float(report["pair_coupled"]["overall"]["balanced_accuracy"])


def default_ba(report: dict[str, Any]) -> float:
    return float(report["default_threshold"]["overall"]["balanced_accuracy"])


def group_rate(report: dict[str, Any]) -> float:
    return float(report["pair_coupled"]["group_metrics"]["group_all_correct_rate"])


def orientation(report: dict[str, Any]) -> float:
    return float(report["pair_coupled"]["group_metrics"]["orientation_accuracy"])


def best_threshold_ba(report: dict[str, Any]) -> float:
    return float(report["best_by_balanced_accuracy"]["balanced_accuracy"])


def best_threshold(report: dict[str, Any]) -> float:
    return float(report["best_by_balanced_accuracy"]["threshold"])


def dataset_row(
    *,
    dataset: str,
    patch_report: dict[str, Any],
    source_expert_report: dict[str, Any],
    patch_threshold_report: dict[str, Any] | None = None,
    zero_shot_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "dataset": dataset,
        "patcheval_adapter_default_ba": default_ba(patch_report),
        "patcheval_adapter_pair_coupled_ba": pair_ba(patch_report),
        "patcheval_adapter_group_all_correct": group_rate(patch_report),
        "patcheval_adapter_orientation": orientation(patch_report),
        "source_expert_pair_coupled_ba": pair_ba(source_expert_report),
        "source_expert_group_all_correct": group_rate(source_expert_report),
        "patcheval_minus_source_expert_ba": round4(pair_ba(patch_report) - pair_ba(source_expert_report)),
    }
    if patch_threshold_report is not None:
        row["patcheval_adapter_best_threshold_ba"] = best_threshold_ba(patch_threshold_report)
        row["patcheval_adapter_best_threshold"] = best_threshold(patch_threshold_report)
    if zero_shot_report is not None:
        row["matched_mixed_pair_coupled_ba"] = pair_ba(zero_shot_report)
        row["patcheval_minus_matched_mixed_ba"] = round4(pair_ba(patch_report) - pair_ba(zero_shot_report))
    return row


def build_report(
    *,
    patch_on_prime: dict[str, Any],
    patch_on_delta: dict[str, Any],
    patch_on_patch: dict[str, Any],
    patch_multiseed: dict[str, Any],
    prime_expert: dict[str, Any],
    delta_expert: dict[str, Any],
    patch_zero_shot: dict[str, Any],
    prime_threshold: dict[str, Any],
    delta_threshold: dict[str, Any],
) -> dict[str, Any]:
    patch_multiseed_mean = float(patch_multiseed["summary"]["pair_coupled_balanced_accuracy"]["mean"])
    patch_multiseed_min = float(patch_multiseed["summary"]["pair_coupled_balanced_accuracy"]["min"])
    patch_multiseed_max = float(patch_multiseed["summary"]["pair_coupled_balanced_accuracy"]["max"])
    rows = [
        dataset_row(
            dataset="PrimeVul-time",
            patch_report=patch_on_prime,
            source_expert_report=prime_expert,
            patch_threshold_report=prime_threshold,
        ),
        dataset_row(
            dataset="DeltaSecommits",
            patch_report=patch_on_delta,
            source_expert_report=delta_expert,
            patch_threshold_report=delta_threshold,
        ),
        {
            "dataset": "PatchEval",
            "patcheval_adapter_default_ba": default_ba(patch_on_patch),
            "patcheval_adapter_pair_coupled_ba": pair_ba(patch_on_patch),
            "patcheval_adapter_multiseed_pair_coupled_ba_mean": patch_multiseed_mean,
            "patcheval_adapter_multiseed_pair_coupled_ba_min": patch_multiseed_min,
            "patcheval_adapter_multiseed_pair_coupled_ba_max": patch_multiseed_max,
            "patcheval_adapter_group_all_correct": group_rate(patch_on_patch),
            "patcheval_adapter_orientation": orientation(patch_on_patch),
            "matched_mixed_pair_coupled_ba": pair_ba(patch_zero_shot),
            "patcheval_minus_matched_mixed_ba": round4(pair_ba(patch_on_patch) - pair_ba(patch_zero_shot)),
        },
    ]
    cross_rows = [row for row in rows if row["dataset"] != "PatchEval"]
    return {
        "status": "ok",
        "scope": "patcheval_cross_source_specialization",
        "protocol": {
            "adapter": "PatchEval source-specific Qwen2.5-Coder-1.5B LoRA, seed42 checkpoint",
            "note": (
                "This report tests whether the PatchEval expert is a general paired-diff detector or a source-specialized adapter. "
                "PatchEval in-domain stability is represented by the separate three-seed summary."
            ),
        },
        "datasets": rows,
        "cross_source_summary": {
            "mean_cross_source_pair_coupled_ba": round4(
                sum(float(row["patcheval_adapter_pair_coupled_ba"]) for row in cross_rows) / len(cross_rows)
            ),
            "mean_cross_source_gap_to_source_expert_ba": round4(
                sum(float(row["patcheval_minus_source_expert_ba"]) for row in cross_rows) / len(cross_rows)
            ),
            "delta_best_threshold_recovery": {
                "best_threshold_ba": best_threshold_ba(delta_threshold),
                "best_threshold": best_threshold(delta_threshold),
                "pair_coupled_ba": pair_ba(patch_on_delta),
            },
            "prime_best_threshold_recovery": {
                "best_threshold_ba": best_threshold_ba(prime_threshold),
                "best_threshold": best_threshold(prime_threshold),
                "pair_coupled_ba": pair_ba(patch_on_prime),
            },
        },
        "conclusion": (
            "The PatchEval adapter transfers non-trivially to PrimeVul-time and DeltaSecommits, but it remains below the matched source experts. "
            "This supports source-aware routing: PatchEval adaptation is useful in-domain, while cross-source deployment should prefer the dataset/source expert when available."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PatchEval Cross-Source Specialization",
        "",
        "This report evaluates whether the PatchEval-specific adapter behaves like a general paired-diff detector or a source-specialized expert.",
        "",
        "## Results",
        "",
        "| Dataset | PatchEval Adapter BA | Source Expert BA | Gap vs Expert | Group All-Correct | Orientation | Best Scalar BA |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["datasets"]:
        source = row.get("source_expert_pair_coupled_ba", row.get("matched_mixed_pair_coupled_ba", "n/a"))
        gap = row.get("patcheval_minus_source_expert_ba", row.get("patcheval_minus_matched_mixed_ba", "n/a"))
        best_scalar = row.get("patcheval_adapter_best_threshold_ba", "n/a")
        lines.append(
            f"| `{row['dataset']}` | `{row['patcheval_adapter_pair_coupled_ba']}` | `{source}` | `{gap}` | "
            f"`{row['patcheval_adapter_group_all_correct']}` | `{row['patcheval_adapter_orientation']}` | `{best_scalar}` |"
        )
    summary = payload["cross_source_summary"]
    lines.extend(
        [
            "",
            "## Cross-Source Summary",
            "",
            f"- Mean cross-source PatchEval-adapter pair-coupled BA: `{summary['mean_cross_source_pair_coupled_ba']}`",
            f"- Mean gap to source expert: `{summary['mean_cross_source_gap_to_source_expert_ba']}`",
            f"- PrimeVul scalar threshold best BA: `{summary['prime_best_threshold_recovery']['best_threshold_ba']}` at threshold `{summary['prime_best_threshold_recovery']['best_threshold']}`; pair-coupled BA: `{summary['prime_best_threshold_recovery']['pair_coupled_ba']}`",
            f"- Delta scalar threshold best BA: `{summary['delta_best_threshold_recovery']['best_threshold_ba']}` at threshold `{summary['delta_best_threshold_recovery']['best_threshold']}`; pair-coupled BA: `{summary['delta_best_threshold_recovery']['pair_coupled_ba']}`",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build PatchEval cross-source specialization report.")
    parser.add_argument("--patch-on-prime", default="reports/secure_code_patcheval_adapter_on_primevul_time_eval_v1.json")
    parser.add_argument("--patch-on-delta", default="reports/secure_code_patcheval_adapter_on_deltasecommits_eval_v1.json")
    parser.add_argument("--patch-on-patch", default="reports/secure_code_patcheval_adapter_pair_diff_eval_v1.json")
    parser.add_argument("--patch-multiseed", default="reports/secure_code_patcheval_adapter_multiseed_v1.json")
    parser.add_argument("--prime-expert", default="reports/secure_code_primevul_time_disjoint_direct_train_v1.json")
    parser.add_argument("--delta-expert", default="reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json")
    parser.add_argument("--patch-zero-shot", default="reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json")
    parser.add_argument("--prime-threshold", default="reports/secure_code_patcheval_adapter_primevul_time_threshold_sweep_v1.json")
    parser.add_argument("--delta-threshold", default="reports/secure_code_patcheval_adapter_delta_threshold_sweep_v1.json")
    parser.add_argument("--json-output", default="reports/secure_code_patcheval_cross_source_specialization_v1.json")
    parser.add_argument("--md-output", default="reports/PATCHEVAL_CROSS_SOURCE_SPECIALIZATION.md")
    args = parser.parse_args()

    payload = build_report(
        patch_on_prime=read_json(args.patch_on_prime),
        patch_on_delta=read_json(args.patch_on_delta),
        patch_on_patch=read_json(args.patch_on_patch),
        patch_multiseed=read_json(args.patch_multiseed),
        prime_expert=read_json(args.prime_expert),
        delta_expert=read_json(args.delta_expert),
        patch_zero_shot=read_json(args.patch_zero_shot),
        prime_threshold=read_json(args.prime_threshold),
        delta_threshold=read_json(args.delta_threshold),
    )
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
