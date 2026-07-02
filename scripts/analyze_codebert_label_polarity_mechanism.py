"""Compute the label-vs-polarity side-order mechanism metrics for CodeBERT,
using the exact same functions applied to Qwen in #47-#49 and #58, so the two
architectures are compared on an identical footing (no new metric definitions).

For each swap variant the metric of interest is the phi coefficient of its
predictions against canonical (from `prediction_independence`): a high positive
phi means the prediction barely moved (the swap is inert), a phi near zero
means near-independence (the swap moved the prediction). The Qwen chain found
label-only swap inert (phi high) but polarity-only swap disruptive (phi ~ 0).
This asks whether a competency-matched CodeBERT reproduces that *ordering*
(polarity more disruptive than labels), not whether it hits identical numbers.

Also reports per-variant accuracy (does polarity-only accuracy collapse with
gold held fixed?) and model-vs-crude-polarity-shortcut row agreement
(reusing `model_shortcut_agreement` from the confound module).

Pure counting over existing predictions; no model is run here.
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
from vrf.polarity_gold_confound import model_shortcut_agreement
from vrf.qwen_mechanism_analysis import prediction_independence


def _norm(value: Any) -> str | None:
    text = str(value).upper()
    if text.startswith("A"):
        return "A"
    if text.startswith("B"):
        return "B"
    return None


def _preds_by_pair(audit_rows, predictions, variant):
    out: dict[str, str] = {}
    for row in audit_rows:
        if row["audit_variant"] != variant:
            continue
        pred = predictions.get(str(row["id"]))
        if pred is None:
            continue
        side = _norm(pred.get("predicted_riskier_side"))
        if side is not None:
            out[str(row["pair_key"])] = side
    return out


def _accuracy(audit_rows, predictions, variant):
    correct = total = 0
    for row in audit_rows:
        if row["audit_variant"] != variant:
            continue
        pred = predictions.get(str(row["id"]))
        if pred is None:
            continue
        side = _norm(pred.get("predicted_riskier_side"))
        gold = _norm(row.get("gold_riskier_side"))
        if side is None or gold is None:
            continue
        total += 1
        correct += side == gold
    return {"n": total, "accuracy": correct / total if total else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_label_polarity_mechanism_audit_v1.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_label_polarity_mechanism_codebert_predictions_512.jsonl",
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_primevul_joint_side_choice_codebert_v1",
    )
    parser.add_argument("--length", type=int, default=512)
    parser.add_argument(
        "--crossvul-audit",
        default="data/processed/secure_code_crossvul_polarity_only_swap_audit_v1.jsonl",
        help="CrossVul audit for the confound-aware shortcut-agreement check",
    )
    parser.add_argument(
        "--crossvul-predictions",
        default="outputs/secure_code_crossvul_label_polarity_codebert_predictions_512.jsonl",
    )
    parser.add_argument(
        "--output",
        default="reports/codebert_label_polarity_mechanism_replication_v1.json",
    )
    args = parser.parse_args()

    audit_rows = read_jsonl(ROOT / args.audit)
    predictions = {str(r["id"]): r for r in read_jsonl(ROOT / args.predictions)}

    canonical = _preds_by_pair(audit_rows, predictions, "canonical")
    label_only = _preds_by_pair(audit_rows, predictions, "label_only_swap")
    polarity_only = _preds_by_pair(audit_rows, predictions, "polarity_only_swap")
    side_swap = _preds_by_pair(audit_rows, predictions, "side_swap")

    variants = ["canonical", "label_only_swap", "polarity_only_swap", "side_swap"]
    accuracy = {v: _accuracy(audit_rows, predictions, v) for v in variants}
    shortcut = {
        v: model_shortcut_agreement(
            [r for r in audit_rows if r["audit_variant"] == v], predictions
        )
        for v in variants
    }

    # CrossVul confound-aware check: does CodeBERT track the crude net-polarity
    # shortcut on CrossVul as heavily as Qwen did (#58: ~0.92)? The CrossVul
    # audit has canonical/polarity_only_swap/side_swap (no label_only_swap).
    crossvul_section: Any = None
    crossvul_audit_path = ROOT / args.crossvul_audit
    crossvul_pred_path = ROOT / args.crossvul_predictions
    if crossvul_audit_path.exists() and crossvul_pred_path.exists():
        cv_audit = read_jsonl(crossvul_audit_path)
        cv_preds = {str(r["id"]): r for r in read_jsonl(crossvul_pred_path)}
        cv_variants = ["canonical", "polarity_only_swap", "side_swap"]
        crossvul_section = {
            "audit": args.crossvul_audit,
            "predictions": args.crossvul_predictions,
            "accuracy": {
                v: _accuracy(cv_audit, cv_preds, v) for v in cv_variants
            },
            "model_vs_crude_polarity_shortcut": {
                v: model_shortcut_agreement(
                    [r for r in cv_audit if r["audit_variant"] == v], cv_preds
                )
                for v in cv_variants
            },
            "note": (
                "Compare model_vs_crude_polarity_shortcut agreement to Qwen's "
                "~0.92 on CrossVul (reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md). "
                "Do not overinterpret CrossVul raw canonical accuracy: #58 "
                "showed CrossVul carries a stronger polarity/gold confound than "
                "PrimeVul."
            ),
        }

    payload = {
        "status": "ok",
        "scope": "codebert_label_polarity_mechanism_replication",
        "checkpoint": args.checkpoint,
        "length": args.length,
        "base_pairs": len(canonical),
        "accuracy": accuracy,
        "prediction_independence_vs_canonical": {
            "label_only_swap": prediction_independence(canonical, label_only),
            "polarity_only_swap": prediction_independence(canonical, polarity_only),
            "side_swap": prediction_independence(canonical, side_swap),
        },
        "cross_check": {
            "note": (
                "polarity_only_swap and side_swap share a byte-identical diff "
                "body and differ only in the 'Side A'/'Side B' words; high "
                "agreement confirms the words are inert for this model too."
            ),
            "polarity_only_swap_vs_side_swap": prediction_independence(
                polarity_only, side_swap
            ),
        },
        "model_vs_crude_polarity_shortcut": shortcut,
        "crossvul_confound_aware_check": crossvul_section,
        "claim_boundary": (
            "Behavioral mechanism evidence on one additional (non-Qwen) "
            "architecture, competency-matched on canonical accuracy. It tests "
            "whether the label-vs-polarity ORDERING (polarity more disruptive "
            "than prose labels) reproduces, not whether numbers match. It does "
            "not claim the mechanism is universal, that all models fail this "
            "way, or that the model internally binds to polarity."
        ),
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
