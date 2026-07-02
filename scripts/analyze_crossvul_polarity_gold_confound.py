"""Measure the polarity/gold confound on CrossVul, paralleling
reports/POLARITY_GOLD_CONFOUND.md's PrimeVul/DeltaSecommits/PatchEval analysis.

Closes the open question flagged in reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md's
CrossVul transfer section: CrossVul's higher raw canonical accuracy and higher
polarity flip rate than PrimeVul *may* be explained by a stronger net-polarity/
gold correlation there, and that was explicitly "not separately measured" at
the time. This measures it, reusing the same counting functions from
src/vrf/polarity_gold_confound.py (no new metric definition) against the
350-pair CrossVul polarity-only-swap audit already built for #54's transfer
test -- no new data construction, no model run, no training.

CrossVul differs from the PrimeVul analysis in one structural way: the
checkpoint was never trained on CrossVul (it is evaluated zero-shot), so there
is no CrossVul training-orientation-balance to measure the way
scripts/analyze_polarity_gold_confound.py does for the PrimeVul training set.
The applicable analog is the EVAL-set gold-side balance (are Side A/Side B
assigned independently of vulnerability in the audit itself), reported
directly from the audit rows.
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
    eval_set_gold_side_balance,
    model_shortcut_agreement,
    polarity_gold_correlation,
    source_pair_cleanliness,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl",
        help="raw CrossVul pair-diff source used to build the #54 audit's base pairs",
    )
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_crossvul_polarity_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_crossvul_baseline_polarity_audit_predictions_1024.jsonl",
        help="baseline (pre-repair) checkpoint predictions on the CrossVul audit, from #54",
    )
    parser.add_argument(
        "--output",
        default="reports/crossvul_polarity_gold_confound_v1.json",
    )
    args = parser.parse_args()

    source_rows = read_jsonl(ROOT / args.source)
    audit_rows = read_jsonl(ROOT / args.audit)
    predictions_path = ROOT / args.predictions
    predictions = (
        {str(row["id"]): row for row in read_jsonl(predictions_path)}
        if predictions_path.exists()
        else {}
    )

    canonical_rows = [r for r in audit_rows if r.get("audit_variant") == "canonical"]

    variants = ["canonical", "polarity_only_swap", "side_swap"]
    eval_by_variant: dict[str, Any] = {}
    for variant in variants:
        rows = [r for r in audit_rows if r.get("audit_variant") == variant]
        eval_by_variant[variant] = {
            "polarity_gold_correlation": polarity_gold_correlation(rows),
            "model_vs_shortcut": (
                model_shortcut_agreement(rows, predictions) if predictions else None
            ),
        }

    payload = {
        "status": "ok",
        "scope": "crossvul_polarity_gold_confound",
        "purpose": (
            "Measures whether CrossVul's higher canonical accuracy / worse "
            "polarity flip behavior (reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md "
            "CrossVul transfer section) could be explained by a stronger "
            "net-polarity/gold correlation there than on PrimeVul, rather than "
            "by better secure-code reasoning on the unseen source. Dataset: the "
            "same 350 CrossVul base pairs used for #54's repair-transfer test."
        ),
        "source": {
            "path": args.source,
            "pair_cleanliness": source_pair_cleanliness(source_rows),
        },
        "eval": {
            "benchmark": args.audit,
            "predictions": args.predictions if predictions else None,
            "gold_side_balance": eval_set_gold_side_balance(canonical_rows),
            "by_variant": eval_by_variant,
        },
        "claim_boundary": (
            "This is a dataset/presentation-structure analysis, not a "
            "model-quality claim. It measures how Side A/Side B and net "
            "changed-line polarity relate to gold on CrossVul, exactly "
            "paralleling reports/POLARITY_GOLD_CONFOUND.md's PrimeVul analysis, "
            "so the two sources' canonical-accuracy and polarity-sensitivity "
            "numbers can be interpreted on a comparable footing. It does not "
            "by itself establish that the model reasons better or worse on "
            "either source."
        ),
    }
    write_json(ROOT / args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
