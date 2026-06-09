from __future__ import annotations

import argparse
import json
from pathlib import Path


INVARIANT_INTERVENTIONS = (
    "format_normalized",
    "identifier_normalized",
    "metadata_removed",
    "nonsecurity_padding",
)


def summarize(report: dict) -> dict:
    rows = report["by_intervention"]
    invariant_rates = [float(rows[name]["unexpected_change_rate"]) for name in INVARIANT_INTERVENTIONS]
    return {
        "mean_invariant_unexpected_change_rate": sum(invariant_rates) / len(invariant_rates),
        "side_order_violation_rate": float(rows["side_order_swapped"]["unexpected_change_rate"]),
        "context_truncation_unexpected_change_rate": float(rows["context_truncated"]["unexpected_change_rate"]),
        "base_accuracy": float(rows["metadata_removed"]["base_expected_label_accuracy"]),
        "by_intervention": {
            name: float(rows[name]["unexpected_change_rate"])
            for name in (*INVARIANT_INTERVENTIONS, "side_order_swapped", "context_truncated")
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare counterfactual robustness of learned joint variants.")
    parser.add_argument("--synthetic", default="reports/secure_code_primevul_counterfactual_synthetic_joint_v1.json")
    parser.add_argument(
        "--consistency",
        default="reports/secure_code_primevul_counterfactual_real_consistency_v1.json",
    )
    parser.add_argument("--output", default="reports/secure_code_primevul_joint_counterfactual_comparison_v1.json")
    parser.add_argument("--markdown-output", default="reports/PRIMEVUL_JOINT_COUNTERFACTUAL_COMPARISON.md")
    args = parser.parse_args()

    synthetic = summarize(json.loads(Path(args.synthetic).read_text(encoding="utf-8")))
    consistency = summarize(json.loads(Path(args.consistency).read_text(encoding="utf-8")))
    report = {
        "status": "ok",
        "scope": "primevul_joint_counterfactual_comparison",
        "synthetic_supervised": synthetic,
        "real_plus_consistency": consistency,
        "synthetic_minus_consistency": {
            key: synthetic[key] - consistency[key]
            for key in (
                "mean_invariant_unexpected_change_rate",
                "side_order_violation_rate",
                "context_truncation_unexpected_change_rate",
                "base_accuracy",
            )
        },
        "interpretation": (
            "Synthetic reversal is not exact text-level gold, but direct synthetic supervision is stronger than the "
            "current weak consistency objective on both held-out accuracy and most counterfactual stability measures."
        ),
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# PrimeVul Joint Counterfactual Comparison",
        "",
        "Both checkpoints recompute their own 400 base predictions and use the same 768-token inference cap.",
        "",
        "| Variant | Base accuracy | Mean invariant change | Side-order violation | Context-truncation change |",
        "| --- | ---: | ---: | ---: | ---: |",
        (
            f"| Synthetic-supervised | `{synthetic['base_accuracy']:.4f}` | "
            f"`{synthetic['mean_invariant_unexpected_change_rate']:.4f}` | "
            f"`{synthetic['side_order_violation_rate']:.4f}` | "
            f"`{synthetic['context_truncation_unexpected_change_rate']:.4f}` |"
        ),
        (
            f"| Real + consistency | `{consistency['base_accuracy']:.4f}` | "
            f"`{consistency['mean_invariant_unexpected_change_rate']:.4f}` | "
            f"`{consistency['side_order_violation_rate']:.4f}` | "
            f"`{consistency['context_truncation_unexpected_change_rate']:.4f}` |"
        ),
        "",
        "Lower change/violation rates are better; higher base accuracy is better.",
        "",
        "The synthetic-supervised checkpoint is stronger overall. Real + consistency improves metadata-removal invariance, but it does not yet provide a better accuracy-robustness tradeoff.",
        "",
    ]
    Path(args.markdown_output).write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
