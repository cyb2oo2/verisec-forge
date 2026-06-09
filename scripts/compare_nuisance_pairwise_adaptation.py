from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl, write_json


def exact_mcnemar(repaired: int, introduced: int) -> float:
    discordant = repaired + introduced
    if discordant == 0:
        return 1.0
    smaller = min(repaired, introduced)
    return min(
        1.0,
        2.0 * sum(math.comb(discordant, index) for index in range(smaller + 1)) / (2**discordant),
    )


def relation_success(row: dict[str, Any]) -> bool:
    relation = str(row["expected_relation"])
    if relation == "invariant":
        return int(row["base_pred"]) == int(row["intervention_pred"])
    if relation == "equivariant_flip":
        return int(row["intervention_pred"]) == 1 - int(row["base_pred"])
    return (
        bool(row.get("intervention_abstain"))
        or float(row["intervention_confidence"]) <= float(row["base_confidence"])
    )


def paired_relation_comparison(
    baseline_rows: list[dict[str, Any]],
    adapted_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    baseline = {str(row["id"]): row for row in baseline_rows}
    adapted = {str(row["id"]): row for row in adapted_rows}
    if set(baseline) != set(adapted):
        raise ValueError("Counterfactual prediction IDs do not match")
    interventions = sorted({str(row["intervention"]) for row in baseline_rows})
    report = {}
    for intervention in interventions:
        ids = [row_id for row_id, row in baseline.items() if row["intervention"] == intervention]
        baseline_success = [relation_success(baseline[row_id]) for row_id in ids]
        adapted_success = [relation_success(adapted[row_id]) for row_id in ids]
        repaired = sum(not before and after for before, after in zip(baseline_success, adapted_success, strict=True))
        introduced = sum(before and not after for before, after in zip(baseline_success, adapted_success, strict=True))
        report[intervention] = {
            "rows": len(ids),
            "baseline_success_rate": sum(baseline_success) / len(ids),
            "adapted_success_rate": sum(adapted_success) / len(ids),
            "success_rate_delta": (sum(adapted_success) - sum(baseline_success)) / len(ids),
            "repaired_violations": repaired,
            "introduced_violations": introduced,
            "discordant": repaired + introduced,
            "exact_mcnemar_p": exact_mcnemar(repaired, introduced),
        }
    return report


def paired_orientation_comparison(
    baseline_rows: list[dict[str, Any]],
    adapted_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    baseline = {str(row["pair_key"]): bool(row["correct_orientation"]) for row in baseline_rows}
    adapted = {str(row["pair_key"]): bool(row["correct_orientation"]) for row in adapted_rows}
    if set(baseline) != set(adapted):
        raise ValueError("Pairwise prediction keys do not match")
    repaired = sum(not baseline[key] and adapted[key] for key in baseline)
    introduced = sum(baseline[key] and not adapted[key] for key in baseline)
    return {
        "pairs": len(baseline),
        "baseline_accuracy": sum(baseline.values()) / len(baseline),
        "adapted_accuracy": sum(adapted.values()) / len(adapted),
        "accuracy_delta": (sum(adapted.values()) - sum(baseline.values())) / len(baseline),
        "repaired": repaired,
        "introduced": introduced,
        "discordant": repaired + introduced,
        "exact_mcnemar_p": exact_mcnemar(repaired, introduced),
    }


def render_markdown(report: dict[str, Any]) -> str:
    orientation = report["orientation"]
    lines = [
        "# PrimeVul Targeted Nuisance Adaptation Pilot",
        "",
        "This is a 375-pair pilot adaptation from the synthetic-supervised joint checkpoint. "
        "Both variants are evaluated at 512 tokens. Counterfactual rows use code-only identifier "
        "normalization and recompute each checkpoint's own base predictions.",
        "",
        "## Main Task",
        "",
        "| baseline | adapted | delta | repaired | introduced | McNemar p |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {orientation['baseline_accuracy']:.4f} | {orientation['adapted_accuracy']:.4f} | "
            f"{orientation['accuracy_delta']:+.4f} | {orientation['repaired']} | "
            f"{orientation['introduced']} | {orientation['exact_mcnemar_p']:.6g} |"
        ),
        "",
        "## Counterfactual Relation Success",
        "",
        "| intervention | baseline | adapted | delta | repaired | introduced | McNemar p |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in report["interventions"].items():
        lines.append(
            f"| `{name}` | {row['baseline_success_rate']:.4f} | {row['adapted_success_rate']:.4f} | "
            f"{row['success_rate_delta']:+.4f} | {row['repaired_violations']} | "
            f"{row['introduced_violations']} | {row['exact_mcnemar_p']:.6g} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The pilot is successful only for targeted nuisance robustness, not as a new full-coverage "
            "accuracy result. Any regression on untargeted relations must remain visible when deciding "
            "whether to scale the adaptation.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare the targeted nuisance adaptation with its source checkpoint.")
    parser.add_argument(
        "--baseline-counterfactual",
        default="outputs/secure_code_primevul_counterfactual_synthetic_joint_clean_identifier_v1.jsonl",
    )
    parser.add_argument(
        "--adapted-counterfactual",
        default="outputs/secure_code_primevul_counterfactual_nuisance_joint_v1.jsonl",
    )
    parser.add_argument(
        "--baseline-pairs",
        default="outputs/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_eval512_predictions.jsonl",
    )
    parser.add_argument(
        "--adapted-pairs",
        default="outputs/secure_code_primevul_joint_pairwise_nuisance_qwen15b_lora_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_primevul_nuisance_pairwise_adaptation_pilot_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/PRIMEVUL_NUISANCE_PAIRWISE_ADAPTATION_PILOT.md",
    )
    args = parser.parse_args()

    report = {
        "status": "ok",
        "method": "targeted_nuisance_pairwise_adaptation_pilot",
        "orientation": paired_orientation_comparison(
            read_jsonl(args.baseline_pairs),
            read_jsonl(args.adapted_pairs),
        ),
        "interventions": paired_relation_comparison(
            read_jsonl(args.baseline_counterfactual),
            read_jsonl(args.adapted_counterfactual),
        ),
        "claim_boundary": (
            "This is a 375-pair pilot. Counterfactual gains do not establish external robustness or "
            "replace the full-coverage pair-coupled result."
        ),
    }
    write_json(args.output, report)
    Path(args.markdown_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
