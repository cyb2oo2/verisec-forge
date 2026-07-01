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


def _accuracy(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    variant: str,
) -> dict[str, Any]:
    correct = 0
    total = 0
    for row in audit_rows:
        if row["audit_variant"] != variant:
            continue
        prediction = predictions.get(row["id"])
        if prediction is None:
            continue
        total += 1
        correct += str(prediction["predicted_riskier_side"]) == str(
            row["gold_riskier_side"]
        )
    return {"n": total, "accuracy": correct / total if total else None}


def _predictions_by_variant(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    variant: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in audit_rows:
        if row["audit_variant"] != variant:
            continue
        prediction = predictions.get(row["id"])
        if prediction is None:
            continue
        result[str(row["pair_key"])] = str(prediction["predicted_riskier_side"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize the polarity-only-swap audit: accuracy per variant plus "
            "prediction independence (phi) of polarity_only_swap and side_swap "
            "against canonical, and the polarity_only_swap<->side_swap "
            "agreement that shows the 'Side A'/'Side B' words are inert."
        ),
    )
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_qwen_mechanism_polarity_only_swap_audit_v1_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1",
    )
    parser.add_argument("--length", type=int, default=1024)
    parser.add_argument(
        "--output",
        default="reports/secure_code_qwen_polarity_only_swap_vs_structural_swap_v1.json",
    )
    args = parser.parse_args()

    audit_rows = read_jsonl(ROOT / args.audit)
    predictions = {str(row["id"]): row for row in read_jsonl(ROOT / args.predictions)}

    canonical = _predictions_by_variant(audit_rows, predictions, "canonical")
    polarity = _predictions_by_variant(audit_rows, predictions, "polarity_only_swap")
    side_swap = _predictions_by_variant(audit_rows, predictions, "side_swap")

    base_pairs = len(canonical)
    payload = {
        "status": "ok",
        "scope": "qwen_polarity_only_swap_vs_structural_swap",
        "checkpoint": args.checkpoint,
        "length": args.length,
        "base_pairs": base_pairs,
        "results": {
            "canonical": _accuracy(audit_rows, predictions, "canonical"),
            "polarity_only_swap": {
                **_accuracy(audit_rows, predictions, "polarity_only_swap"),
                "independence_vs_canonical": prediction_independence(
                    canonical, polarity
                ),
            },
            "side_swap": {
                **_accuracy(audit_rows, predictions, "side_swap"),
                "independence_vs_canonical": prediction_independence(
                    canonical, side_swap
                ),
            },
        },
        "cross_check": {
            "note": (
                "polarity_only_swap and side_swap have byte-identical diff "
                "bodies and differ only in the 'Side A'/'Side B' words; a high "
                "positive phi confirms the words are inert, so the "
                "polarity_only_swap effect is attributable to the diff "
                "polarity flip alone."
            ),
            "polarity_only_swap_vs_side_swap": prediction_independence(
                polarity, side_swap
            ),
        },
        "claim_boundary": (
            "Isolates diff hunk polarity as the driver of the side-swap "
            "failure: relabeling alone did not move the prediction "
            "(label_only_swap, prior report), whereas flipping polarity with "
            "the labels and gold held fixed does. One checkpoint, one length, "
            f"{base_pairs} pairs, observational/correlational only."
        ),
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
