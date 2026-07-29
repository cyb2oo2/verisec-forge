from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def fmt(value: float) -> str:
    return f"{value:.4f}".rstrip("0").rstrip(".")


def metric(value: float, name: str = "BA") -> str:
    return f"{name} `{fmt(value)}`"


def build_rows() -> list[dict[str, str]]:
    progressive = read_json("reports/PRIMEVUL_PROGRESSIVE_CONTROLS.json")
    significance = read_json("reports/secure_code_primevul_pair_coupled_significance_v1.json")
    time_direct = read_json("reports/secure_code_primevul_time_disjoint_direct_train_v1.json")
    delta_only = read_json("reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json")
    patch_zero = read_json("reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json")
    patch_multiseed = read_json("reports/secure_code_patcheval_adapter_multiseed_v1.json")
    mixture = read_json("reports/secure_code_three_source_adapter_mixture_v1.json")
    router = read_json("reports/secure_code_learned_router_claim_boundary_v1.json")

    progressive_rows = {row["stage"]: row for row in progressive["rows"]}
    diff_only = significance["diff_only_three_seed"]
    pair_coupled = significance["pair_coupled_multisplit"]
    strict_delta = significance["strict_pair_minus_bucket"]
    patch_summary = patch_multiseed["summary"]["pair_coupled_balanced_accuracy"]
    routed_delta = mixture["routed_minus_single"]

    return [
        {
            "claim_area": "Shortcut diagnosis",
            "setting": "PrimeVul same-source detector",
            "primary_result": metric(progressive_rows["Same-source baseline"]["value"]),
            "uncertainty_or_control": "Recall `0.9709`, specificity `0.9339`; treated as artifact-sensitive.",
            "reviewer_safe_interpretation": "High standard-split score motivates stricter paired evaluation; it is not the headline breakthrough.",
            "artifact": progressive_rows["Same-source baseline"]["artifact"],
        },
        {
            "claim_area": "Shortcut diagnosis",
            "setting": "Same detector on vulnerable/fixed paired stress",
            "primary_result": metric(progressive_rows["Paired stress test"]["value"]),
            "uncertainty_or_control": "Best threshold `0.9999`; near chance.",
            "reviewer_safe_interpretation": "The easy same-source result does not survive paired patch structure.",
            "artifact": progressive_rows["Paired stress test"]["artifact"],
        },
        {
            "claim_area": "Negative controls",
            "setting": "Metadata/candidate/counterpart-only controls",
            "primary_result": f"best control {metric(progressive_rows['Shortcut controls']['value'])}",
            "uncertainty_or_control": "Metadata-only `0.5022`, candidate-only `0.5078`, counterpart-only `0.5156` BA.",
            "reviewer_safe_interpretation": "These controls remove the diff and bound only metadata/single-side context. They do not protect the paired-diff formulation; the character-level diff control does not stay near chance.",
            "artifact": progressive_rows["Shortcut controls"]["artifact"],
        },
        {
            "claim_area": "Paired diff reasoning",
            "setting": "PrimeVul diff-only paired detector",
            "primary_result": f"mean {metric(diff_only['mean'])}",
            "uncertainty_or_control": f"3 seeds, range `{fmt(diff_only['ci95_low'])}-{fmt(diff_only['ci95_high'])}`.",
            "reviewer_safe_interpretation": "Diff-only paired reasoning is the credible base formulation after shortcut diagnosis.",
            "artifact": progressive_rows["Paired diff detector"]["artifact"],
        },
        {
            "claim_area": "Metadata removal",
            "setting": "PrimeVul diff-only without Project/CVE/CWE prompt metadata",
            "primary_result": metric(progressive_rows["No-metadata check"]["value"]),
            "uncertainty_or_control": "Threshold `0.8`.",
            "reviewer_safe_interpretation": "The paired-diff signal does not depend on obvious prompt metadata.",
            "artifact": progressive_rows["No-metadata check"]["artifact"],
        },
        {
            "claim_area": "Task-structured decoding",
            "setting": "Pair-coupled decoding over held-out pair-key splits",
            "primary_result": f"mean {metric(pair_coupled['mean'])}",
            "uncertainty_or_control": (
                f"5 splits, CI `[{fmt(pair_coupled['ci95_low'])}, {fmt(pair_coupled['ci95_high'])}]`; "
                f"strict pair-minus-bucket BA delta `{fmt(strict_delta['balanced_accuracy_delta']['mean'])}` "
                f"CI `[{fmt(strict_delta['balanced_accuracy_delta']['ci95_low'])}, {fmt(strict_delta['balanced_accuracy_delta']['ci95_high'])}]`."
            ),
            "reviewer_safe_interpretation": "This is the main method-like contribution because it uses paired task structure.",
            "artifact": "reports/secure_code_primevul_pair_coupled_significance_v1.json",
        },
        {
            "claim_area": "External validation",
            "setting": "PrimeVul true time-disjoint direct train <=2020, eval >=2021",
            "primary_result": metric(time_direct["pair_coupled"]["overall"]["balanced_accuracy"]),
            "uncertainty_or_control": f"`{time_direct['split']['rows']}` rows, `{time_direct['split']['unique_pair_count']}` pair groups.",
            "reviewer_safe_interpretation": "Temporal split keeps paired-diff signal strong under later-CVE evaluation.",
            "artifact": "reports/secure_code_primevul_time_disjoint_direct_train_v1.json",
        },
        {
            "claim_area": "External validation",
            "setting": "DeltaSecommits C/C++ source-specific adapter",
            "primary_result": metric(delta_only["pair_coupled"]["overall"]["balanced_accuracy"]),
            "uncertainty_or_control": f"`{delta_only['split']['rows']}` balanced rows, `{delta_only['split']['unique_pair_count']}` pair groups.",
            "reviewer_safe_interpretation": "Second-source C/C++ paired patches support the paired-diff formulation outside PrimeVul.",
            "artifact": "reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json",
        },
        {
            "claim_area": "External validation",
            "setting": "PatchEval zero-shot matched-mixed checkpoint",
            "primary_result": metric(patch_zero["pair_coupled"]["overall"]["balanced_accuracy"]),
            "uncertainty_or_control": f"`{patch_zero['split']['rows']}` rows across Go/JavaScript/Python-oriented repairs.",
            "reviewer_safe_interpretation": "Third-source cross-language transfer is harder but remains above chance.",
            "artifact": "reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json",
        },
        {
            "claim_area": "External adaptation",
            "setting": "PatchEval source-specific adapter, 3 seeds",
            "primary_result": f"mean {metric(patch_summary['mean'])}",
            "uncertainty_or_control": f"Range `{fmt(patch_summary['min'])}-{fmt(patch_summary['max'])}`.",
            "reviewer_safe_interpretation": "PatchEval adaptation helps but is seed-sensitive, so report mean/range rather than best seed.",
            "artifact": "reports/secure_code_patcheval_adapter_multiseed_v1.json",
        },
        {
            "claim_area": "Source-aware routing",
            "setting": "Three-source source-routed adapter mixture",
            "primary_result": metric(mixture["systems"][1]["overall"]["balanced_accuracy"]),
            "uncertainty_or_control": f"Single matched-mixed BA `{fmt(mixture['systems'][0]['overall']['balanced_accuracy'])}`; delta `{fmt(routed_delta['balanced_accuracy'])}`.",
            "reviewer_safe_interpretation": "Source-specific experts provide a small aggregate gain over one mixed checkpoint.",
            "artifact": "reports/secure_code_three_source_adapter_mixture_v1.json",
        },
        {
            "claim_area": "Learned router boundary",
            "setting": "Learned diff-body-only source/expert router",
            "primary_result": "routed BA `0.8664`",
            "uncertainty_or_control": (
                f"BA delta `{fmt(router['closed_world_statistical_support']['learned_minus_single_ba'])}`, "
                f"CI `[{fmt(router['closed_world_statistical_support']['learned_minus_single_ba_ci95'][0])}, {fmt(router['closed_world_statistical_support']['learned_minus_single_ba_ci95'][1])}]`; "
                "leave-one-source routed-minus-oracle range `[-0.025, -0.0077]`."
            ),
            "reviewer_safe_interpretation": "Closed-world expert selection is supported; open-set source discovery is not claimed.",
            "artifact": "reports/secure_code_learned_router_claim_boundary_v1.json",
        },
        {
            "claim_area": "Evidence-coupled audit loop",
            "setting": "Predicted-side hunk/window localization",
            "primary_result": f"top-1 `{fmt(progressive_rows['Evidence propagation']['value'])}`",
            "uncertainty_or_control": "Side-correct top-1 `0.7610`; side-wrong top-1 `0.0632`.",
            "reviewer_safe_interpretation": "Evidence quality depends on upstream side decisions; current evidence labels remain pseudo-label/triage.",
            "artifact": progressive_rows["Evidence propagation"]["artifact"],
        },
        {
            "claim_area": "Safe correction protocol",
            "setting": "Evidence-conditioned project-holdout safe flip gate",
            "primary_result": "accept precision `1.0`",
            "uncertainty_or_control": "Accepted `9`, introduced `0`; small queue and stress-invalidated earlier strict gate.",
            "reviewer_safe_interpretation": "Useful precision-first review protocol, not a deployable large-scale automatic flipper.",
            "artifact": progressive_rows["Safe flip gate"]["artifact"],
        },
    ]


def render_markdown(rows: list[dict[str, str]]) -> str:
    lines = [
        "# Final Submission Statistics",
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
        "This table compresses the reviewer-facing evidence into one submission-oriented view. It favors claim boundaries over raw score maximization: high same-source scores are treated as shortcut diagnostics, while paired diff reasoning, pair-coupled decoding, external validation, source-aware routing, and evidence triage are separated.",
        "",
        "## Main Table",
        "",
        "| Claim area | Setting | Primary result | Uncertainty / control | Reviewer-safe interpretation | Artifact |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {claim_area} | {setting} | {primary_result} | {uncertainty_or_control} | {reviewer_safe_interpretation} | `{artifact}` |".format(
                **row
            )
        )
    lines.extend(
        [
            "",
            "## Reading Notes",
            "",
            "- The same-source PrimeVul `0.9524` result is included as a cautionary artifact diagnosis, not as the headline.",
            "- The strict pair-coupled claim is pair-coupled decoding versus bucket routing on the same held-out pair-key splits.",
            "- External validation currently supports paired patch/diff reasoning across PrimeVul time-disjoint, DeltaSecommits, and PatchEval, but broader open-set source shift remains future work.",
            "- Learned source routing should be described as closed-world source-aware expert selection. Leave-one-source stress prevents claiming unseen-source expert discovery.",
            "- Evidence localization and safe flip gates are audit-loop diagnostics until non-AI adjudication confirms evidence spans.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build final submission statistics table.")
    parser.add_argument("--output-md", default="reports/FINAL_SUBMISSION_STATISTICS.md")
    parser.add_argument("--output-json", default="reports/FINAL_SUBMISSION_STATISTICS.json")
    args = parser.parse_args()

    rows = build_rows()
    md_path = ROOT / args.output_md
    json_path = ROOT / args.output_json
    md_path.write_text(render_markdown(rows), encoding="utf-8")
    json_path.write_text(json.dumps({"status": "ok", "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "markdown": args.output_md, "json": args.output_json, "rows": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
