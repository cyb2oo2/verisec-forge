"""Clustered replacement for the five-overlapping-split significance summary.

The previous summary bootstrapped five held-out "splits" that overlap pairwise
at Jaccard ~0.53 over the same 874 pair groups, with model predictions frozen
across all five. Those are not five independent confirmations, and resampling
them estimates partition noise rather than generalisation.

This script computes the same comparison with ``pair_key`` groups as the unit:
a clustered bootstrap for the metric difference and an exact sign test at the
group level.

Usage::

    python scripts/build_primevul_pair_coupled_clustered_statistics.py \
        --json-output reports/secure_code_primevul_pair_coupled_clustered_statistics_v1.json \
        --md-output reports/PRIMEVUL_PAIR_COUPLED_CLUSTERED_STATISTICS.md
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from scripts.evaluate_primevul_bucket_router_calibrated import (  # noqa: E402
    build_report_for_threshold,
    filter_by_pair_keys,
    split_pair_keys,
)
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling  # noqa: E402
from vrf.artifact_guard import require_artifact  # noqa: E402
from vrf.io_utils import read_json, read_jsonl, write_json  # noqa: E402
from vrf.stats_cluster import group_sign_test, paired_cluster_bootstrap_diff  # noqa: E402

DEFAULT_CALIBRATED = "reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json"

REMEDIATION = {
    "produced_by": "scripts/evaluate_primevul_bucket_router_calibrated.py",
    "obtain": (
        "python scripts/download_reproducibility_bundle.py "
        "--bundle-name primevul_router_and_evidence_coupled_inputs --restore"
    ),
    "purpose": "clustered pair-coupled statistics",
}


def balanced_accuracy(rows: Sequence[dict[str, Any]], key: str) -> float:
    tp = sum(1 for row in rows if row["gold"] == 1 and row[key] == 1)
    fn = sum(1 for row in rows if row["gold"] == 1 and row[key] == 0)
    tn = sum(1 for row in rows if row["gold"] == 0 and row[key] == 0)
    fp = sum(1 for row in rows if row["gold"] == 0 and row[key] == 1)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return (recall + specificity) / 2


def metric_over_groups(groups: Sequence[Sequence[dict[str, Any]]], key: str) -> float:
    return balanced_accuracy([row for group in groups for row in group], key)


def build_report(*, calibrated_path: str, margin: float, seed: int, iterations: int) -> dict[str, Any]:
    require_artifact(calibrated_path, **REMEDIATION)
    calibrated = read_json(calibrated_path)
    for key in ("dataset", "default_predictions", "bucket_predictions"):
        require_artifact(calibrated[key], **REMEDIATION)

    dataset_rows = read_jsonl(calibrated["dataset"])
    split = split_pair_keys(
        dataset_rows,
        calibration_fraction=float(calibrated["split"]["calibration_fraction"]),
        seed=int(calibrated["split"]["seed"]),
    )
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])
    thresholds = calibrated["selection"]["thresholds"]

    bucket_rows, _ = build_report_for_threshold(
        eval_rows,
        default_predictions_path=calibrated["default_predictions"],
        bucket_predictions_path=calibrated["bucket_predictions"],
        bucket=calibrated["bucket"],
        default_threshold=float(thresholds["default"]),
        bucket_threshold=float(thresholds["bucket"]),
    )
    coupled_rows, coupling_counts = apply_pair_coupling(bucket_rows, margin=margin)
    coupled_by_id = {str(row["id"]): row for index, row in enumerate(coupled_rows)}

    merged: list[dict[str, Any]] = []
    for row in bucket_rows:
        coupled = coupled_by_id.get(str(row["id"]), row)
        merged.append(
            {
                "id": row["id"],
                "pair_key": row.get("pair_key") or row["id"],
                "gold": int(row["gold"]),
                "bucket_router": int(row["pred"]),
                "pair_coupled": int(coupled["pred"]),
            }
        )

    buckets: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in merged:
        buckets[str(row["pair_key"])].append(row)
    groups = list(buckets.values())

    clustered = paired_cluster_bootstrap_diff(
        groups,
        lambda sample: metric_over_groups(sample, "bucket_router"),
        lambda sample: metric_over_groups(sample, "pair_coupled"),
        iterations=iterations,
        seed=seed,
    )

    wins = losses = 0
    for group in groups:
        coupled_correct = all(row["gold"] == row["pair_coupled"] for row in group)
        bucket_correct = all(row["gold"] == row["bucket_router"] for row in group)
        if coupled_correct and not bucket_correct:
            wins += 1
        elif bucket_correct and not coupled_correct:
            losses += 1

    return {
        "scope": "primevul_pair_coupled_clustered_statistics",
        "supersedes": "reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md",
        "why_superseded": {
            "previous_unit": "five held-out split seeds of one frozen prediction set",
            "previous_problem": (
                "the five splits overlap pairwise at Jaccard ~0.53 over the same 874 pair groups and no "
                "model was retrained, so they are not independent confirmations and the interval "
                "described partition noise"
            ),
            "new_unit": "pair_key group",
        },
        "margin": margin,
        "coupling_counts": coupling_counts,
        "independent_units": len(groups),
        "rows": len(merged),
        "balanced_accuracy": {
            "bucket_router": round(metric_over_groups(groups, "bucket_router"), 4),
            "pair_coupled": round(metric_over_groups(groups, "pair_coupled"), 4),
        },
        "clustered_delta": clustered,
        "group_level_sign_test": group_sign_test(wins, losses),
        "caveat": (
            "This quantifies pair coupling against the same model without the constraint. It does "
            "NOT establish that the model contributes the delta, because the constraint is closed-world "
            "knowledge the baseline does not receive. See "
            "reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md."
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    delta = report["clustered_delta"]
    sign = report["group_level_sign_test"]
    why = report["why_superseded"]
    return "\n".join(
        [
            "# PrimeVul Pair-Coupled Clustered Statistics",
            "",
            "Generated by `scripts/build_primevul_pair_coupled_clustered_statistics.py`.",
            "",
            f"Supersedes `{report['supersedes']}`.",
            "",
            "## Why the previous statistics were replaced",
            "",
            f"- Previous unit of inference: {why['previous_unit']}",
            f"- Problem: {why['previous_problem']}",
            f"- New unit of inference: `{why['new_unit']}`",
            "",
            "## Result",
            "",
            "| quantity | value |",
            "| --- | ---: |",
            f"| independent units (`pair_key` groups) | `{report['independent_units']}` |",
            f"| evaluation rows | `{report['rows']}` |",
            f"| bucket router balanced accuracy | `{report['balanced_accuracy']['bucket_router']}` |",
            f"| pair-coupled balanced accuracy | `{report['balanced_accuracy']['pair_coupled']}` |",
            f"| clustered delta | `{delta['point']}` |",
            f"| 95% clustered bootstrap CI | `[{delta['ci95_low']}, {delta['ci95_high']}]` |",
            "",
            "## Group-level paired sign test",
            "",
            f"- groups where only pair coupling is fully correct: `{sign['wins']}`",
            f"- groups where only the bucket router is fully correct: `{sign['losses']}`",
            f"- discordant groups: `{sign['discordant_groups']}`",
            f"- two-sided exact p-value: `{sign['two_sided_p_value_display']}`",
            "",
            "## Caveat",
            "",
            report["caveat"],
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Clustered pair-coupled statistics.")
    parser.add_argument("--calibrated-report", default=DEFAULT_CALIBRATED)
    parser.add_argument("--margin", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--json-output", default="reports/secure_code_primevul_pair_coupled_clustered_statistics_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_PAIR_COUPLED_CLUSTERED_STATISTICS.md")
    args = parser.parse_args()

    report = build_report(
        calibrated_path=args.calibrated_report,
        margin=args.margin,
        seed=args.seed,
        iterations=args.iterations,
    )
    write_json(str(REPO_ROOT / args.json_output), report)
    (REPO_ROOT / args.md_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("balanced_accuracy", "clustered_delta", "group_level_sign_test")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
