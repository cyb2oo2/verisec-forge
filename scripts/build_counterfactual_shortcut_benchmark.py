from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.counterfactuals import build_interventions
from vrf.io_utils import read_jsonl, write_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="Build controlled counterfactual shortcut interventions.")
    parser.add_argument("--input", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--output", default="data/processed/secure_code_primevul_counterfactual_interventions_v1.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_counterfactual_interventions_v1.json")
    parser.add_argument("--max-pairs", type=int, default=200)
    args = parser.parse_args()

    rows = read_jsonl(ROOT / args.input)
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)

    output_rows = []
    pair_count = 0
    for pair_key in sorted(grouped):
        pair = grouped[pair_key]
        if len(pair) != 2:
            continue
        for row, counterpart in [(pair[0], pair[1]), (pair[1], pair[0])]:
            for intervention in build_interventions(row, counterpart):
                intervention["id"] = f"{row['id']}::{intervention['intervention']}"
                output_rows.append(intervention)
        pair_count += 1
        if pair_count >= args.max_pairs:
            break
    write_jsonl(ROOT / args.output, output_rows)
    counts: dict[str, int] = {}
    for row in output_rows:
        counts[row["intervention"]] = counts.get(row["intervention"], 0) + 1
    summary = {
        "status": "ok",
        "pairs": pair_count,
        "base_rows": pair_count * 2,
        "intervention_rows": len(output_rows),
        "interventions": dict(sorted(counts.items())),
        "relations": {
            "metadata_removed": "invariant",
            "identifier_normalized": "invariant",
            "format_normalized": "invariant",
            "nonsecurity_padding": "invariant",
            "side_order_swapped": "equivariant_flip",
            "context_truncated": "abstention_sensitivity",
        },
        "output": args.output.replace("\\", "/"),
    }
    (ROOT / args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
