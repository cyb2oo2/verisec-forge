from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl


PRIMARY_VARIANTS = (
    "canonical",
    "side_swap",
    "canonical_no_metadata",
    "padding_pre_diff",
    "padding_post_diff",
    "padding_post_diff_terminal_phrase",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the six-variant cross-model relational audit."
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_qwen_mechanism_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_cross_model_relational_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_cross_model_relational_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    rows = [
        row
        for row in read_jsonl(ROOT / args.input)
        if row["audit_variant"] in PRIMARY_VARIANTS
    ]
    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "pairs": len(
            {
                (str(row["dataset"]), str(row["pair_key"]))
                for row in rows
            }
        ),
        "rows": len(rows),
        "variants": {
            variant: sum(row["audit_variant"] == variant for row in rows)
            for variant in PRIMARY_VARIANTS
        },
        "protocol": {
            "canonical": "base forced-decision accuracy",
            "side_swap": "side-order equivariance",
            "canonical_no_metadata": "metadata-removal relation",
            "padding_pre_diff": "prompt-level pre-diff nuisance",
            "padding_post_diff": "terminal representation sensitivity",
            "padding_post_diff_terminal_phrase": (
                "decision-consistency recovery from a terminal "
                "task-completion phrase"
            ),
        },
        "excluded_stress": [
            "padding_mid_diff_malformed_stress",
            "Delta representation-specific variants",
        ],
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
