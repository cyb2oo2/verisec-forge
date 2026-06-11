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
from vrf.relational_runtime import materialize_runtime_rows


def summarize_runtime_rows(rows, args) -> dict:
    accountings = [row["runtime_accounting"] for row in rows]
    by_template = {}
    for template in sorted({row["transformation_template"] for row in rows}):
        template_rows = [
            row for row in rows if row["transformation_template"] == template
        ]
        template_accounting = [
            row["runtime_accounting"] for row in template_rows
        ]
        achieved = [
            row["achieved_budget_ratio"]
            for row in template_accounting
            if row.get("achieved_budget_ratio") is not None
        ]
        by_template[template] = {
            "rows": len(template_rows),
            "critical_hunk_truncated_rows": sum(
                row["critical_hunk_truncated"]
                for row in template_accounting
            ),
            "transformation_introduced_critical_truncation_rows": sum(
                row.get(
                    "transformation_introduced_critical_truncation", False
                )
                for row in template_accounting
            ),
            "mean_critical_line_visibility_ratio": sum(
                row["critical_line_visibility_ratio"]
                for row in template_accounting
            )
            / max(1, len(template_accounting)),
            "achieved_budget_ratio": (
                {
                    "min": min(achieved),
                    "mean": sum(achieved) / len(achieved),
                    "max": max(achieved),
                }
                if achieved
                else None
            ),
        }
    by_suite = {}
    for suite in sorted({row["sampling_suite"] for row in rows}):
        suite_rows = [row for row in rows if row["sampling_suite"] == suite]
        by_suite[suite] = {
            "rows": len(suite_rows),
            "critical_hunk_truncated_rows": sum(
                row["runtime_accounting"]["critical_hunk_truncated"]
                for row in suite_rows
            ),
            "transformation_introduced_critical_truncation_rows": sum(
                row["runtime_accounting"].get(
                    "transformation_introduced_critical_truncation", False
                )
                for row in suite_rows
            ),
        }
    return {
        "status": "ok",
        "benchmark": args.benchmark.replace("\\", "/"),
        "model_id": args.model_id,
        "tokenizer_id": args.tokenizer,
        "max_length": args.max_length,
        "truncation_side": args.truncation_side,
        "add_special_tokens": not args.no_special_tokens,
        "offset_mapping_quality": "exact_fast_tokenizer",
        "rows": len(rows),
        "critical_hunk_truncated_rows": sum(
            row["critical_hunk_truncated"] for row in accountings
        ),
        "transformation_introduced_critical_truncation_rows": sum(
            row.get("transformation_introduced_critical_truncation", False)
            for row in accountings
        ),
        "by_sampling_suite": by_suite,
        "by_template": by_template,
        "claim_boundary": (
            "This artifact validates model-specific token visibility only. "
            "It contains no model predictions and supports no robustness claim."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize model-specific VeriPatch-RR runtime accounting."
    )
    parser.add_argument(
        "--benchmark",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument("--max-length", type=int, required=True)
    parser.add_argument(
        "--truncation-side", choices=["left", "right"], default="right"
    )
    parser.add_argument(
        "--no-special-tokens", action="store_true"
    )
    parser.add_argument("--local-files-only", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output")
    args = parser.parse_args()

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer, local_files_only=args.local_files_only
    )
    rows = materialize_runtime_rows(
        read_jsonl(ROOT / args.benchmark),
        tokenizer=tokenizer,
        model_id=args.model_id,
        tokenizer_id=args.tokenizer,
        max_length=args.max_length,
        truncation_side=args.truncation_side,
        add_special_tokens=not args.no_special_tokens,
    )
    write_jsonl(ROOT / args.output, rows)
    summary = summarize_runtime_rows(rows, args)
    if args.summary_output:
        write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
