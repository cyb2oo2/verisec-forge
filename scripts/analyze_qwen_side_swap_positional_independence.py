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
from vrf.qwen_mechanism_analysis import prediction_independence


def predictions_by_variant(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    by_variant: dict[str, dict[str, str]] = {}
    for row in audit_rows:
        prediction = predictions.get(row["id"])
        if prediction is None:
            continue
        by_variant.setdefault(row["audit_variant"], {})[row["pair_key"]] = str(
            prediction["predicted_riskier_side"]
        )
    return by_variant


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Test whether predictions under an intervention are statistically "
            "independent of canonical predictions for the same pair, or whether "
            "they remain correlated (content-aware) -- distinguishing content-"
            "blind failures from mislabeled-but-content-aware ones."
        ),
    )
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_qwen_mechanism_side_swap_terminal_phrase_audit_v1.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_qwen_mechanism_side_swap_terminal_phrase_audit_v1_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--baseline-variant",
        default="canonical",
    )
    parser.add_argument(
        "--comparison-variant",
        action="append",
        dest="comparison_variants",
        default=None,
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_qwen_side_swap_positional_independence_v1.json",
    )
    args = parser.parse_args()

    audit_rows = read_jsonl(ROOT / args.audit)
    predictions = {str(row["id"]): row for row in read_jsonl(ROOT / args.predictions)}
    by_variant = predictions_by_variant(audit_rows, predictions)

    comparison_variants = args.comparison_variants or sorted(
        v for v in by_variant if v != args.baseline_variant
    )
    baseline = by_variant[args.baseline_variant]
    results = {
        variant: prediction_independence(baseline, by_variant[variant])
        for variant in comparison_variants
        if variant in by_variant
    }

    payload = {
        "status": "ok",
        "scope": "qwen_side_swap_positional_independence",
        "baseline_variant": args.baseline_variant,
        "results": results,
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
