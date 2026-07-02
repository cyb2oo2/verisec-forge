"""Decompose the held-out nuisance-transform transfer result, per family.

For each of the five families in `src/vrf/nuisance_transfer.py`, computes the
same four-way decomposition used for the PrimeVul (#54) and CrossVul transfer
results -- baseline independent, baseline antisymmetric inference (projection
null), repaired independent, repaired antisymmetric inference -- plus the
fine-tuning delta over the null and its exact McNemar test. Reuses
`src/vrf/repair_evaluation.py` functions unchanged; introduces no new metric
definition. No model is run here.
"""

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

from vrf.io_utils import read_jsonl, write_json
from vrf.nuisance_transfer import NUISANCE_FAMILIES
from vrf.repair_evaluation import (
    compare_antisymmetric_inference,
    independent_inference_accuracy,
    independent_inference_relation_violation,
)


def analyze_family(
    family: str,
    audit_rows: list[dict[str, Any]],
    baseline_predictions: dict[str, dict[str, Any]],
    repaired_predictions: dict[str, dict[str, Any]],
    *,
    truncation_summary: dict[str, Any],
) -> dict[str, Any]:
    canonical_variant = f"canonical__{family}"
    side_swap_variant = f"side_swap__{family}"
    family_rows = [
        row
        for row in audit_rows
        if row.get("audit_variant") in (canonical_variant, side_swap_variant)
    ]

    baseline_independent = independent_inference_accuracy(
        family_rows, baseline_predictions, variant=canonical_variant
    )
    repaired_independent = independent_inference_accuracy(
        family_rows, repaired_predictions, variant=canonical_variant
    )
    baseline_violation = independent_inference_relation_violation(
        family_rows,
        baseline_predictions,
        canonical_variant=canonical_variant,
        side_swap_variant=side_swap_variant,
    )
    repaired_violation = independent_inference_relation_violation(
        family_rows,
        repaired_predictions,
        canonical_variant=canonical_variant,
        side_swap_variant=side_swap_variant,
    )
    antisym = compare_antisymmetric_inference(
        family_rows,
        baseline_predictions,
        repaired_predictions,
        canonical_variant=canonical_variant,
        side_swap_variant=side_swap_variant,
    )

    projection_null_delta = None
    if (
        baseline_independent is not None
        and antisym["baseline_antisymmetric_accuracy"] is not None
    ):
        projection_null_delta = (
            antisym["baseline_antisymmetric_accuracy"] - baseline_independent
        )

    canonical_truncation = truncation_summary.get("by_template", {}).get(
        canonical_variant, {}
    )
    side_swap_truncation = truncation_summary.get("by_template", {}).get(
        side_swap_variant, {}
    )

    return {
        "family": family,
        "pair_count": antisym["baseline_n"],
        "canonical_accuracy": {
            "baseline_independent": baseline_independent,
            "repaired_independent": repaired_independent,
            "baseline_antisymmetric_inference_null": antisym[
                "baseline_antisymmetric_accuracy"
            ],
            "repaired_antisymmetric_inference": antisym[
                "repaired_antisymmetric_accuracy"
            ],
        },
        "transformed_view_accuracy": {
            "note": (
                "The transformed rendering IS the canonical rendering in this "
                "dataset (that is the point of the nuisance transform); "
                "compare to the PrimeVul #54 canonical baseline (0.660 "
                "independent / 0.7067 antisym-null / 0.7333 repaired-antisym)."
            ),
            "baseline_independent": baseline_independent,
            "repaired_independent": repaired_independent,
        },
        "relation_violation_rate": {
            "baseline_independent": baseline_violation,
            "repaired_independent": repaired_violation,
        },
        "projection_null_delta": projection_null_delta,
        "fine_tuning_delta_over_null": antisym["fine_tuning_delta_over_null"],
        "mcnemar": antisym["mcnemar"],
        "runtime_accounting": {
            "canonical": {
                "rows": canonical_truncation.get("rows"),
                "critical_hunk_truncated_rows": canonical_truncation.get(
                    "critical_hunk_truncated_rows"
                ),
                "transformation_introduced_critical_truncation_rows": canonical_truncation.get(
                    "transformation_introduced_critical_truncation_rows"
                ),
            },
            "side_swap": {
                "rows": side_swap_truncation.get("rows"),
                "critical_hunk_truncated_rows": side_swap_truncation.get(
                    "critical_hunk_truncated_rows"
                ),
                "transformation_introduced_critical_truncation_rows": side_swap_truncation.get(
                    "transformation_introduced_critical_truncation_rows"
                ),
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl",
    )
    parser.add_argument(
        "--baseline-predictions",
        default="outputs/secure_code_nuisance_transfer_baseline_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--repaired-predictions",
        default="outputs/secure_code_nuisance_transfer_repaired_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--truncation-summary",
        default="reports/secure_code_nuisance_transfer_audit_runtime1024_summary_v1.json",
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_repair_antisymmetric_nuisance_transfer_v1.json",
    )
    args = parser.parse_args()

    audit_rows = read_jsonl(ROOT / args.audit)
    baseline_predictions = {
        str(r["id"]): r for r in read_jsonl(ROOT / args.baseline_predictions)
    }
    repaired_predictions = {
        str(r["id"]): r for r in read_jsonl(ROOT / args.repaired_predictions)
    }
    truncation_summary = json.loads(
        (ROOT / args.truncation_summary).read_text(encoding="utf-8")
    )

    by_family = {
        family: analyze_family(
            family,
            audit_rows,
            baseline_predictions,
            repaired_predictions,
            truncation_summary=truncation_summary,
        )
        for family in NUISANCE_FAMILIES
    }

    bonferroni_threshold = 0.05 / len(NUISANCE_FAMILIES)
    uncorrected_positive_significant = [
        family
        for family, result in by_family.items()
        if result["fine_tuning_delta_over_null"] is not None
        and result["fine_tuning_delta_over_null"] > 0
        and result["mcnemar"]["p_value"] < 0.05
    ]
    corrected_positive_significant = [
        family
        for family in uncorrected_positive_significant
        if by_family[family]["mcnemar"]["p_value"] < bonferroni_threshold
    ]
    negative_delta_families = [
        family
        for family, result in by_family.items()
        if result["fine_tuning_delta_over_null"] is not None
        and result["fine_tuning_delta_over_null"] < 0
    ]

    if corrected_positive_significant:
        verdict = (
            "The fine-tuning delta over the projection null survives on "
            f"{len(corrected_positive_significant)}/{len(NUISANCE_FAMILIES)} "
            "held-out nuisance families at a Bonferroni-corrected "
            f"significance threshold (p<{bonferroni_threshold:.3f} for "
            f"{len(NUISANCE_FAMILIES)} families tested). This is preliminary "
            "transferable evidence, not a validated repair -- see "
            "reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md for the full claim "
            "boundary."
        )
    else:
        verdict = (
            f"No family survives a Bonferroni-corrected significance "
            f"threshold (p<{bonferroni_threshold:.3f} for "
            f"{len(NUISANCE_FAMILIES)} families tested; smallest observed "
            f"p-value is "
            f"{min(r['mcnemar']['p_value'] for r in by_family.values()):.4f}). "
            f"{len(uncorrected_positive_significant)}/{len(NUISANCE_FAMILIES)} "
            "families show an uncorrected p<0.05 positive delta, but "
            f"{len(negative_delta_families)}/{len(NUISANCE_FAMILIES)} families "
            "show the fine-tuned model performing WORSE than the frozen "
            "baseline under the antisymmetric decision "
            f"({', '.join(negative_delta_families) if negative_delta_families else 'none'}). "
            "A repair effect that reverses sign across held-out "
            "presentation changes is evidence AGAINST a robust, "
            "content-based transferable effect, consistent with the "
            "CrossVul external-source result (delta shrinks from +0.0267, "
            "p=0.002 in-distribution to +0.0086, p=0.508 on an unseen "
            "source). Conclusion: the antisymmetric-readout architecture "
            "remains a useful structural fix; the current fine-tuning "
            "objective is not validated as a transferable learned repair."
        )

    payload = {
        "status": "ok",
        "scope": "repair_antisymmetric_nuisance_transfer_v1",
        "purpose": (
            "Test whether the fine-tuning delta over the antisymmetric "
            "projection null (significant in-distribution on PrimeVul, "
            "p=0.002; not significant on CrossVul, p=0.508) survives "
            "held-out nuisance transforms never seen during training or "
            "the original polarity-only-swap evaluation."
        ),
        "audit": args.audit,
        "families": by_family,
        "multiple_comparisons": {
            "families_tested": len(NUISANCE_FAMILIES),
            "bonferroni_corrected_threshold": bonferroni_threshold,
            "uncorrected_p_below_0_05_and_positive": uncorrected_positive_significant,
            "corrected_p_below_threshold_and_positive": corrected_positive_significant,
            "negative_delta_families": negative_delta_families,
        },
        "comparison_reference": {
            "primevul_in_distribution": {
                "fine_tuning_delta_over_null": 0.026666666666666616,
                "mcnemar_p_value": 0.0024939179420471,
            },
            "crossvul_external_source": {
                "fine_tuning_delta_over_null": 0.008571428571428563,
                "mcnemar_p_value": 0.5078125,
            },
        },
        "verdict": verdict,
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
