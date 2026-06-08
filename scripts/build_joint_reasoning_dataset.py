from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.joint_reasoning import build_joint_pair_record, summarize_joint_records


def main() -> int:
    parser = argparse.ArgumentParser(description="Build pair-level joint secure patch reasoning records.")
    parser.add_argument("--dataset", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--evidence", default="outputs/secure_code_primevul_pair_evidence_localization_v1.jsonl")
    parser.add_argument("--output", default="data/processed/secure_code_primevul_joint_reasoning_eval_v1.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_joint_reasoning_dataset_v1.json")
    parser.add_argument("--evidence-limit", type=int, default=5)
    args = parser.parse_args()

    grouped: dict[str, list[dict]] = {}
    for row in read_jsonl(ROOT / args.dataset):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)
    evidence_by_id = {str(row["id"]): row for row in read_jsonl(ROOT / args.evidence)}
    records = [
        build_joint_pair_record(pair_key, rows, evidence_by_id, evidence_limit=args.evidence_limit)
        for pair_key, rows in sorted(grouped.items())
        if len(rows) == 2
    ]
    write_jsonl(ROOT / args.output, records)
    summary = {
        "status": "ok",
        "scope": "primevul_joint_reasoning_dataset",
        "output": args.output.replace("\\", "/"),
        "target_contract": {
            "side_choice": "A/B vulnerable side classification",
            "evidence_ranking": "rank hunk/window candidates for the chosen side",
            "confidence": "calibrated confidence target when context target is available",
            "insufficient_context": "abstention target when evidence/context is insufficient",
        },
        "summary": summarize_joint_records(records),
        "limitations": [
            "Evidence targets are pseudo-localization labels until human annotation is merged.",
            "Insufficient-context targets are only weak labels unless supplied by the human annotation protocol.",
            "This is a data contract for a learned joint model; it is not itself a trained model result.",
        ],
    }
    (ROOT / args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
