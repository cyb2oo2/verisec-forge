"""Evaluate a predictions file against the preregistered repair criteria.

Run on the current checkpoint's polarity-audit predictions to produce the
pre-repair baseline (which is expected to FAIL every relational criterion), and
later on a repaired model's predictions with ``--baseline-canonical-accuracy``
set so canonical non-inferiority is judged against the model being repaired.

See docs/REPAIR_EXPERIMENT_PREREGISTRATION.md. No model is run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl
from vrf.repair_evaluation import evaluate_repair_criteria
from vrf.reproducibility import capture_artifact_provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_qwen_mechanism_polarity_only_swap_audit_v1_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--baseline-canonical-accuracy",
        type=float,
        default=None,
        help="pre-repair canonical accuracy; set when scoring a repaired model",
    )
    parser.add_argument(
        "--label",
        default="pre_repair_baseline",
        help="tag recorded in the output (e.g. pre_repair_baseline, repaired_v1)",
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_repair_criteria_pre_repair_baseline_v1.json",
    )
    args = parser.parse_args()

    audit_rows = read_jsonl(ROOT / args.audit)
    predictions = {
        str(row["id"]): row for row in read_jsonl(ROOT / args.predictions)
    }
    result = evaluate_repair_criteria(
        audit_rows,
        predictions,
        baseline_canonical_accuracy=args.baseline_canonical_accuracy,
    )
    payload = {
        "status": "ok",
        "scope": "repair_criteria_evaluation",
        "label": args.label,
        "audit": args.audit,
        "predictions": args.predictions,
        "provenance": capture_artifact_provenance(
            ROOT,
            source_paths=[args.audit, args.predictions],
            code_paths=[
                "scripts/evaluate_repair_criteria.py",
                "src/vrf/repair_evaluation.py",
                "src/vrf/relational_evaluation.py",
                "src/vrf/reproducibility.py",
            ],
        ),
        **result,
    }
    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
