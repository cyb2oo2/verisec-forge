from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def read_predictions(path: Path) -> dict[str, bool]:
    rows = [json.loads(line) for line in path.open(encoding="utf-8")]
    return {str(row["pair_key"]): bool(row["correct_orientation"]) for row in rows}


def exact_mcnemar_pvalue(repaired: int, introduced: int) -> float:
    discordant = repaired + introduced
    if not discordant:
        return 1.0
    tail = min(repaired, introduced)
    probability = 2 * sum(math.comb(discordant, index) for index in range(tail + 1)) / (2**discordant)
    return min(1.0, probability)


def compare(baseline: dict[str, bool], candidate: dict[str, bool]) -> dict[str, float | int]:
    keys = sorted(set(baseline) & set(candidate))
    repaired = sum(not baseline[key] and candidate[key] for key in keys)
    introduced = sum(baseline[key] and not candidate[key] for key in keys)
    return {
        "pairs": len(keys),
        "baseline_accuracy": sum(baseline[key] for key in keys) / len(keys),
        "candidate_accuracy": sum(candidate[key] for key in keys) / len(keys),
        "delta": (repaired - introduced) / len(keys),
        "repaired": repaired,
        "introduced": introduced,
        "mcnemar_exact_pvalue": exact_mcnemar_pvalue(repaired, introduced),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare learned joint pairwise variants on identical held-out pairs.")
    parser.add_argument(
        "--synthetic",
        default="outputs/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--real",
        default="outputs/secure_code_primevul_joint_pairwise_real_qwen15b_lora_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--consistency",
        default="outputs/secure_code_primevul_joint_pairwise_real_consistency_qwen15b_lora_v1_predictions.jsonl",
    )
    parser.add_argument("--output", default="reports/secure_code_primevul_joint_pairwise_variant_comparison_v1.json")
    args = parser.parse_args()

    predictions = {
        "synthetic_supervised": read_predictions(Path(args.synthetic)),
        "real_only": read_predictions(Path(args.real)),
        "real_plus_consistency": read_predictions(Path(args.consistency)),
    }
    report = {
        "status": "ok",
        "scope": "primevul_joint_pairwise_variant_comparison",
        "comparisons": {
            "real_to_consistency": compare(predictions["real_only"], predictions["real_plus_consistency"]),
            "synthetic_to_consistency": compare(predictions["synthetic_supervised"], predictions["real_plus_consistency"]),
            "synthetic_to_real": compare(predictions["synthetic_supervised"], predictions["real_only"]),
        },
        "interpretation": (
            "Consistency regularization yields a small paired improvement over real-only supervision, while synthetic "
            "label supervision remains substantially stronger on this held-out set. Counterfactual stress is required "
            "before interpreting the synthetic-supervised advantage as robust semantic improvement."
        ),
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
