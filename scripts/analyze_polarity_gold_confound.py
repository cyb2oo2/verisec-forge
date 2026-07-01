"""Measure the polarity/gold confound behind the side-order mechanism arc.

Produces the numbers cited in docs/TASK_FORMULATION.md and
reports/POLARITY_GOLD_CONFOUND.md:

* training orientation balance (is naive both-orientation augmentation already
  present?);
* net changed-line polarity vs gold on the evaluation benchmark (how predictive
  is the task-illegitimate feature?);
* row-level agreement between the model and the crude polarity shortcut (does
  the model reduce to it?).

Pure counting over existing rows -- no model is trained or run.
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
from vrf.polarity_gold_confound import (
    model_shortcut_agreement,
    orientation_balance,
    polarity_gold_correlation,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--train",
        default="data/processed/secure_code_primevul_joint_side_choice_train_v1.jsonl",
        help="joint side-choice training data that produced the checkpoint",
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
        "--output",
        default="reports/secure_code_polarity_gold_confound_v1.json",
    )
    args = parser.parse_args()

    train_rows = read_jsonl(ROOT / args.train)
    audit_rows = read_jsonl(ROOT / args.audit)
    predictions = {
        str(row["id"]): row for row in read_jsonl(ROOT / args.predictions)
    }

    variants = ["canonical", "polarity_only_swap", "side_swap"]
    eval_by_variant: dict[str, Any] = {}
    for variant in variants:
        rows = [r for r in audit_rows if r.get("audit_variant") == variant]
        eval_by_variant[variant] = {
            "polarity_gold_correlation": polarity_gold_correlation(rows),
            "model_vs_shortcut": model_shortcut_agreement(rows, predictions),
        }

    payload = {
        "status": "ok",
        "scope": "polarity_gold_confound",
        "train": {
            "dataset": args.train,
            "orientation_balance": orientation_balance(train_rows),
            "polarity_gold_correlation": polarity_gold_correlation(
                train_rows, gold_key="vulnerable_side"
            ),
        },
        "eval": {
            "benchmark": args.audit,
            "predictions": args.predictions,
            "by_variant": eval_by_variant,
        },
        "claim_boundary": (
            "Rendering orientation is de-confounded from gold in both training "
            "(balanced forward/reverse, vulnerable side ~50/50, every pair in "
            "both orientations) and the eval benchmark (Side A/B assigned "
            "independently of vulnerability). Net changed-line polarity remains "
            "predictive of gold because real fixes are additive, so it is a "
            "task-illegitimate-but-predictive feature under the "
            "candidate-identity task -- a spurious correlation, not a "
            "non-predictive quirk. The model's polarity sensitivity is real but "
            "does not reduce to the crude net-polarity line-count heuristic "
            "(~56% row-level agreement)."
        ),
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
