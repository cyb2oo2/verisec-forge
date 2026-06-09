from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.build_primevul_pair_context_dataset import build_pair_text
from vrf.io_utils import read_jsonl, write_jsonl


def source_pair_key(row: dict[str, Any]) -> str:
    return "|".join(
        [
            str(row.get("project") or "unknown"),
            str(row.get("commit_id") or "unknown"),
            str(row.get("cve") or "unknown"),
        ]
    )


def side_choice_row(
    candidate: dict[str, Any],
    counterpart: dict[str, Any],
    *,
    pair_instance_key: str,
    orientation: str,
) -> dict[str, Any]:
    return {
        "id": f"{pair_instance_key}::{orientation}",
        "pair_key": pair_instance_key,
        "source_pair_key": source_pair_key(candidate),
        "text": build_pair_text(candidate, counterpart, text_mode="diff_no_metadata"),
        "label": int(bool(candidate.get("has_vulnerability"))),
        "vulnerable_side": "B" if bool(candidate.get("has_vulnerability")) else "A",
        "candidate_id": candidate["id"],
        "counterpart_id": counterpart["id"],
        "orientation": orientation,
    }


def build_real_bidirectional_rows(
    paired_rows: list[dict[str, Any]],
    *,
    excluded_source_keys: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    output: list[dict[str, Any]] = []
    skipped_non_adjacent_pair = 0
    skipped_excluded = 0
    skipped_metadata_mismatch = 0
    for index in range(0, len(paired_rows) - 1, 2):
        first, second = paired_rows[index], paired_rows[index + 1]
        labels = {bool(first.get("has_vulnerability")), bool(second.get("has_vulnerability"))}
        if labels != {False, True}:
            skipped_non_adjacent_pair += 1
            continue
        if source_pair_key(first) != source_pair_key(second):
            skipped_metadata_mismatch += 1
            continue
        source_key = source_pair_key(first)
        if source_key in excluded_source_keys:
            skipped_excluded += 1
            continue
        vulnerable = first if bool(first.get("has_vulnerability")) else second
        safe = second if vulnerable is first else first
        pair_instance_key = f"{source_key}|{vulnerable['id']}|{safe['id']}"
        output.extend(
            [
                side_choice_row(vulnerable, safe, pair_instance_key=pair_instance_key, orientation="vulnerable_candidate"),
                side_choice_row(safe, vulnerable, pair_instance_key=pair_instance_key, orientation="safe_candidate"),
            ]
        )
    summary = {
        "input_rows": len(paired_rows),
        "excluded_source_keys": len(excluded_source_keys),
        "real_pair_instances": len(output) // 2,
        "output_rows": len(output),
        "label_counts": {
            "0": sum(row["label"] == 0 for row in output),
            "1": sum(row["label"] == 1 for row in output),
        },
        "skipped_non_adjacent_pair": skipped_non_adjacent_pair,
        "skipped_metadata_mismatch": skipped_metadata_mismatch,
        "skipped_excluded": skipped_excluded,
    }
    return output, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build real bidirectional PrimeVul side-choice training rows.")
    parser.add_argument("--input", default="data/processed/secure_code_primevul_paired_metadata.jsonl")
    parser.add_argument("--eval", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--output", default="data/processed/secure_code_primevul_real_joint_side_choice_train_v1.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_real_joint_side_choice_train_v1.json")
    args = parser.parse_args()

    eval_source_keys = {str(row.get("pair_key") or source_pair_key(row)) for row in read_jsonl(ROOT / args.eval)}
    rows, summary = build_real_bidirectional_rows(read_jsonl(ROOT / args.input), excluded_source_keys=eval_source_keys)
    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "scope": "primevul_real_bidirectional_joint_side_choice_train",
        "output": args.output.replace("\\", "/"),
        **summary,
    }
    (ROOT / args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
