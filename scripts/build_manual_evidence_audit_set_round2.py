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

from vrf.evidence_audit import DEFAULT_REVIEW_QUEUE_PATHS, load_review_queue_rows, select_audit_rows, summarize_audit_rows
from vrf.io_utils import ensure_parent, read_jsonl, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a second-round manual evidence-span audit set, excluding audit_ids already used in round 1.",
    )
    parser.add_argument("--input", action="append", dest="inputs", default=None)
    parser.add_argument(
        "--exclude-from",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
        help="Round-1 audit JSONL whose audit_ids should be excluded from the new sample.",
    )
    parser.add_argument("--output", default="data/processed/secure_code_primevul_manual_evidence_audit_round2_v1.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_manual_evidence_audit_round2_v1_summary.json")
    parser.add_argument("--report-output", default="reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET_ROUND2.md")
    parser.add_argument("--sample-size", type=int, default=20)
    parser.add_argument("--seed", type=int, default=20260630)
    return parser.parse_args()


def render_report(summary: dict[str, object]) -> str:
    rows = summary["rows"]
    total = summary["total_candidates"]
    excluded = summary["excluded_round1_rows"]
    excluded_pair_keys = summary["excluded_round1_pair_keys"]
    source_unique = summary["unique_pair_keys_in_source_queues"]
    unique = summary["unique_pair_keys"]
    pool_counts = summary["pool_counts"]
    exhausted = rows == 0
    return "\n".join(
        [
            "# PrimeVul Manual Evidence Audit Set (Round 2)",
            "",
            "This is the second-round manual evidence-span audit target, sampled from the same four",
            "side-inversion review queues as round 1, excluding every `audit_id` *and* every `pair_key`",
            "already used in `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md` -- the same review queue row",
            "can appear multiple times across the four pools at different ranks/seeds, so deduplicating by",
            "`audit_id` alone is not sufficient.",
            "",
            "## Summary",
            "",
            f"- Round-1 rows excluded: `{excluded}`",
            f"- Round-1 pair keys excluded: `{excluded_pair_keys}`",
            f"- Unique pair keys across all four source queues: `{source_unique}`",
            f"- Total candidate rows before exclusion and pair-key deduplication: `{total}`",
            f"- Materialized round-2 rows: `{rows}`",
            f"- Unique pair keys: `{unique}`",
            f"- Output dataset: `{summary['output_path']}`",
            "",
            (
                "**This source is exhausted: `0` new pair keys remain.** The four review queues "
                f"contain only `{source_unique}` unique pair keys in total, and round 1's audit set "
                "already covers all of them. Widening the human-confirmed evidence set further "
                "requires a new upstream side-inversion candidate generation run (a different rank "
                "range, gap threshold, or seed family), not resampling these existing queue files."
                if exhausted
                else "New round-2 candidates were found; proceed with an AI pilot annotation pass "
                "before classifying into review queues."
            ),
            "",
            "## Pool Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(pool_counts.items())],
            "",
            "## Annotation Contract",
            "",
            "Same as round 1: `human_vulnerable_side`, `evidence_side`, `evidence_quality`,",
            "`selected_window_ids`, `label_issue`, `notes`. This audit set ships with `annotation: null`",
            "for every row; it requires an AI pilot pass (matching round 1's `codex_pilot` convention)",
            "before `scripts/build_manual_evidence_pilot_findings.py` can classify rows into the",
            "high-quality-disagreement and insufficient-context queues for human confirmation.",
            "",
        ]
    )


def exclude_round1_candidates(
    all_rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    excluded_ids = {str(row["audit_id"]) for row in excluded_rows}
    excluded_pair_keys = {str(row["pair_key"]) for row in excluded_rows}
    return [
        row
        for row in all_rows
        if str(row["audit_id"]) not in excluded_ids and str(row["pair_key"]) not in excluded_pair_keys
    ]


def main() -> int:
    args = parse_args()
    inputs = args.inputs or DEFAULT_REVIEW_QUEUE_PATHS
    excluded_rows = read_jsonl(ROOT / args.exclude_from)
    excluded_ids = {str(row["audit_id"]) for row in excluded_rows}
    excluded_pair_keys = {str(row["pair_key"]) for row in excluded_rows}

    all_rows = load_review_queue_rows([ROOT / path for path in inputs])
    candidates = exclude_round1_candidates(all_rows, excluded_rows)
    selected = select_audit_rows(candidates, sample_size=args.sample_size, seed=args.seed)

    write_jsonl(ROOT / args.output, selected)
    payload = summarize_audit_rows(selected, total_candidates=len(all_rows), output_path=args.output)
    payload["excluded_round1_rows"] = len(excluded_ids)
    payload["excluded_round1_pair_keys"] = len(excluded_pair_keys)
    payload["unique_pair_keys_in_source_queues"] = len({str(row["pair_key"]) for row in all_rows})
    payload["output_path"] = args.output.replace("\\", "/")
    payload["requested_sample_size"] = args.sample_size
    write_json(ROOT / args.summary_output, payload)
    report_path = ensure_parent(ROOT / args.report_output)
    report_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
