from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_json, write_json


def find_main_row(main_results: dict[str, Any], system: str) -> dict[str, Any]:
    for row in main_results["rows"]:
        if row["system"] == system:
            return row
    raise KeyError(f"Missing main-results row: {system}")


def first_coverage(report: dict[str, Any], section: str, scorer: str, *, k: int = 1) -> float:
    for row in report[section][scorer]:
        if int(row["k"]) == k:
            return float(row["coverage"])
    raise KeyError(f"Missing coverage row: {section}.{scorer} k={k}")


def build_rows(
    main_results: dict[str, Any],
    pair_coupled: dict[str, Any],
    predicted_side: dict[str, Any],
    gate_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    same_source = find_main_row(main_results, "same-source detector")
    paired_stress = find_main_row(main_results, "same-source detector on paired eval")
    metadata = find_main_row(main_results, "metadata-only control")
    candidate = find_main_row(main_results, "candidate-only control")
    counterpart = find_main_row(main_results, "counterpart-only control")
    no_metadata = find_main_row(main_results, "diff-only detector, no metadata")
    negative_control_max = max(row["balanced_accuracy"] for row in [metadata, candidate, counterpart])
    pair_summary = pair_coupled["summary"]
    gate_project = gate_summary["pool_summaries"]["project_holdout_top5"]["best_zero_introduced"]
    return [
        {
            "stage": "Same-source baseline",
            "question": "Can a standard split look solved?",
            "key_metric": "balanced_accuracy",
            "value": same_source["balanced_accuracy"],
            "supporting_metric": f"recall={same_source['recall']}, specificity={same_source['specificity']}",
            "interpretation": "High score, but treated as artifact-sensitive rather than robust evidence.",
            "artifact": same_source["source"],
        },
        {
            "stage": "Paired stress test",
            "question": "Does the same model survive vulnerable/fixed pairing?",
            "key_metric": "balanced_accuracy",
            "value": paired_stress["balanced_accuracy"],
            "supporting_metric": f"threshold={paired_stress['threshold']}",
            "interpretation": "Near-chance paired behavior invalidates the easy same-source headline.",
            "artifact": paired_stress["source"],
        },
        {
            "stage": "Shortcut controls",
            "question": "Can metadata/candidate/counterpart controls explain the result?",
            "key_metric": "best_control_balanced_accuracy",
            "value": negative_control_max,
            "supporting_metric": "metadata/candidate/counterpart controls",
            "interpretation": "These three controls remove the diff, so they bound metadata and single-side context only. They do NOT protect the paired-diff formulation: a semantics-free character-level diff control reaches 0.8588 under the pair constraint.",
            "artifact": "reports/PRIMEVUL_MAIN_RESULTS.json",
        },
        {
            "stage": "Paired diff detector",
            "question": "Does diff-only reasoning form a stable harder-split signal?",
            "key_metric": "three_seed_mean_balanced_accuracy",
            "value": main_results["summary"]["diff_seed_balanced_accuracy_mean"],
            "supporting_metric": (
                f"range={main_results['summary']['diff_seed_balanced_accuracy_min']}-"
                f"{main_results['summary']['diff_seed_balanced_accuracy_max']}"
            ),
            "interpretation": "WITHDRAWN as a semantic result. Matched by a semantics-free character-level diff control; no advantage beyond diff structure established.",
            "artifact": "reports/PRIMEVUL_MAIN_RESULTS.json",
        },
        {
            "stage": "No-metadata check",
            "question": "Does the paired diff signal depend on Project/CVE/CWE prompt metadata?",
            "key_metric": "balanced_accuracy",
            "value": no_metadata["balanced_accuracy"],
            "supporting_metric": f"threshold={no_metadata['threshold']}",
            "interpretation": "Removing metadata preserves the signal.",
            "artifact": no_metadata["source"],
        },
        {
            "stage": "Pair-coupled decoding",
            "question": "Does enforcing paired consistency improve decisions?",
            "key_metric": "mean_balanced_accuracy",
            "value": pair_summary["pair_balanced_accuracy"]["mean"],
            "supporting_metric": (
                f"delta_bal={pair_summary['pair_minus_bucket_balanced_accuracy']['mean']}, "
                f"delta_group={pair_summary['pair_minus_bucket_group_all_correct']['mean']}"
            ),
            "interpretation": "Pair-coupled decoding gives stable row-level and group-level gains.",
            "artifact": "reports/secure_code_primevul_pair_coupled_multisplit_balanced_v1.json",
        },
        {
            "stage": "Evidence propagation",
            "question": "Is evidence localization independent of side decisions?",
            "key_metric": "predicted_side_top1",
            "value": first_coverage(predicted_side, "coverage", "pair_coupled_predicted_side", k=1),
            "supporting_metric": (
                f"side_correct_top1={first_coverage(predicted_side, 'coverage', 'pair_coupled_predicted_side_correct_only', k=1)}, "
                f"side_wrong_top1={first_coverage(predicted_side, 'coverage', 'pair_coupled_predicted_side_wrong_only', k=1)}"
            ),
            "interpretation": "WITHDRAWN. The target is antisymmetric in the predicted side, so this contrast is an identity of the labelling function, not a measurement.",
            "artifact": "reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json",
        },
        {
            "stage": "Safe flip gate",
            "question": "Can high-confidence side inversions be repaired safely?",
            "key_metric": "project_holdout_accept_precision",
            "value": gate_project["accept_precision"],
            "supporting_metric": (
                f"accepted={gate_project['accepted_rows']}, introduced={gate_project['introduced_side_error_rows']}, "
                f"stress_invalidated={gate_summary['summary']['stress_invalidated_reports']}"
            ),
            "interpretation": "WITHDRAWN as a validated claim. Precision 1.0 rests on 4 accepted pairs (exact 95% CI [0.3976, 1.0]) and the gate was selected on the pool it is reported on.",
            "artifact": "reports/secure_code_primevul_side_inversion_gate_summary_v1.json",
        },
    ]


def build_payload(
    *,
    main_results_path: str = "reports/PRIMEVUL_MAIN_RESULTS.json",
    pair_coupled_path: str = "reports/secure_code_primevul_pair_coupled_multisplit_balanced_v1.json",
    predicted_side_path: str = "reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json",
    gate_summary_path: str = "reports/secure_code_primevul_side_inversion_gate_summary_v1.json",
) -> dict[str, Any]:
    main_results = read_json(main_results_path)
    pair_coupled = read_json(pair_coupled_path)
    predicted_side = read_json(predicted_side_path)
    gate_summary = read_json(gate_summary_path)
    rows = build_rows(main_results, pair_coupled, predicted_side, gate_summary)
    return {
        "summary": {
            "rows": len(rows),
            "headline": "No semantic advantage beyond diff structure was established: a semantics-free character-level diff control matches the detector under the pair constraint (0.8588 vs 0.8596). The contribution is the measurement of shortcut-driven performance.",
            "primary_result": rows[5],
            "main_limitation": "Evidence localization and safe flip gates remain pseudo-label/small-queue diagnostics.",
        },
        "rows": rows,
    }


def format_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Progressive Controls",
        "",
        "",
        "> **CORRECTED — CONTAINS WITHDRAWN RESULTS.**",
        "> Under the closed-world pair constraint the detector reaches balanced accuracy `0.8596`;",
        "> a semantics-free character-level diff structural control reaches `0.8588` on the same",
        "> evaluation population (difference `+0.0008`, pair-group clustered 95% CI",
        "> `[-0.0202, +0.0222]`, sign test 19 vs 18, `p=1.0`).",
        "> **No semantic advantage beyond diff structure was established.**",
        "> The evidence-localization contrast and the `1.0000` safe-flip gate precision are also",
        "> withdrawn. Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).",
        "This table compresses the PrimeVul research story into a small set of controls and system stages. It is designed for project overviews, application material, and reviewer orientation rather than exhaustive experiment comparison.",
        "",
        "## Summary",
        "",
        "![PrimeVul progressive controls](assets/primevul_progressive_controls.svg)",
        "",
        f"- Rows: `{payload['summary']['rows']}`",
        f"- Headline: {payload['summary']['headline']}",
        f"- Main limitation: {payload['summary']['main_limitation']}",
        "",
        "## Progressive Table",
        "",
        "| stage | research question | key metric | value | supporting metric | interpretation |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| {row['stage']} | {row['question']} | {row['key_metric']} | {format_value(row['value'])} | "
            f"{row['supporting_metric']} | {row['interpretation']} |"
        )
    lines.extend(
        [
            "",
            "## Reading Order",
            "",
            "Start with shortcut diagnosis, then paired diff controls, then pair-coupled decoding. Treat evidence localization and safe flip gates as the audit-loop extension, not as the main performance headline.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a compact progressive-controls table for PrimeVul.")
    parser.add_argument("--json-output", default="reports/PRIMEVUL_PROGRESSIVE_CONTROLS.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md")
    args = parser.parse_args()

    payload = build_payload()
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
