"""Combine the existing label-only and polarity-only mechanism audits into one
tokenizer-neutral 4-variant audit (canonical / label_only_swap /
polarity_only_swap / side_swap) on the same 600 base pairs.

This is pure record surgery over already-committed audit rows -- no model is
run, no new pairs are sampled, no transform logic is re-implemented. The two
source audits were verified to share the same 600 pair_keys with byte-identical
canonical rows and identical gold, so the merge is unambiguous:

- canonical, label_only_swap  <- secure_code_qwen_mechanism_label_only_swap_audit_v1
- polarity_only_swap, side_swap <- secure_code_qwen_mechanism_polarity_only_swap_audit_v1

The result feeds the CodeBERT label/polarity mechanism replication
(reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md): the "qwen_mechanism"
naming in the source filenames refers to how the rows were originally built,
not to a Qwen-specific rendering -- the text is a plain candidate-identity diff
prompt that any sequence classifier can score.
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

from vrf.io_utils import read_jsonl, write_json, write_jsonl

LABEL_VARIANTS = ("canonical", "label_only_swap")
POLARITY_VARIANTS = ("polarity_only_swap", "side_swap")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--label-audit",
        default="data/processed/secure_code_qwen_mechanism_label_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--polarity-audit",
        default="data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_label_polarity_mechanism_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_label_polarity_mechanism_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    label_rows = read_jsonl(ROOT / args.label_audit)
    polarity_rows = read_jsonl(ROOT / args.polarity_audit)

    # Verify the canonical rows agree across the two sources (precondition for
    # an unambiguous merge); fail loudly rather than silently pick one.
    label_canonical = {
        r["pair_key"]: (r["text"], r["gold_riskier_side"])
        for r in label_rows
        if r["audit_variant"] == "canonical"
    }
    polarity_canonical = {
        r["pair_key"]: (r["text"], r["gold_riskier_side"])
        for r in polarity_rows
        if r["audit_variant"] == "canonical"
    }
    if set(label_canonical) != set(polarity_canonical):
        raise ValueError("label and polarity audits cover different pair sets")
    mismatches = [k for k in label_canonical if label_canonical[k] != polarity_canonical[k]]
    if mismatches:
        raise ValueError(
            f"canonical text/gold mismatch on {len(mismatches)} pairs; first={mismatches[0]}"
        )

    combined: list[dict[str, Any]] = []
    for row in label_rows:
        if row["audit_variant"] in LABEL_VARIANTS:
            combined.append(row)
    for row in polarity_rows:
        if row["audit_variant"] in POLARITY_VARIANTS:
            combined.append(row)

    # Re-tag the audit family so downstream tooling sees one coherent audit.
    for row in combined:
        row["audit_family"] = "label_polarity_mechanism"

    write_jsonl(ROOT / args.output, combined)
    variants = sorted({r["audit_variant"] for r in combined})
    pair_keys = sorted({r["pair_key"] for r in combined})
    summary = {
        "status": "ok",
        "scope": "label_polarity_mechanism_audit",
        "base_pairs": len(pair_keys),
        "rows": len(combined),
        "variants": variants,
        "rows_per_variant": {
            v: sum(1 for r in combined if r["audit_variant"] == v) for v in variants
        },
        "sources": {
            "label_only": args.label_audit,
            "polarity_only": args.polarity_audit,
        },
        "note": (
            "Tokenizer-neutral merge of two already-committed audits; no model "
            "run, no new sampling. Materialize per model tokenizer/length before "
            "inference."
        ),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
