from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import (
    ANNOTATION_TEMPLATE_FIELDS,
    annotation_progress_summary,
    annotation_template_rows,
    split_annotation_batches,
)
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export small CSV batches for manual evidence annotation.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        default="data/processed/manual_evidence_audit_batches",
    )
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--prefix", default="manual_evidence_audit_v1_batch")
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_manual_evidence_audit_v1_batch_summary.json",
    )
    parser.add_argument(
        "--report-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_PROGRESS.md",
    )
    return parser.parse_args()


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANNOTATION_TEMPLATE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def render_progress_report(summary: dict[str, object]) -> str:
    batch_rows = summary["batches"]
    by_pool = summary["progress"]["by_source_pool"]
    lines = [
        "# PrimeVul Manual Evidence Audit Progress",
        "",
        "This report tracks the CSV batch workflow for the manual evidence-span audit set.",
        "",
        "## Current Progress",
        "",
        f"- Rows: `{summary['progress']['rows']}`",
        f"- Completed annotations: `{summary['progress']['completed_annotations']}`",
        f"- Blank annotations: `{summary['progress']['blank_annotations']}`",
        f"- Invalid annotations: `{summary['progress']['invalid_annotations']}`",
        f"- Completion rate: `{summary['progress']['completion_rate']}`",
        "",
        "## Batch Files",
        "",
        *[
            f"- `{batch['path']}`: `{batch['rows']}` rows"
            for batch in batch_rows
        ],
        "",
        "## Source Pool Progress",
        "",
        *[
            f"- `{pool}`: "
            + ", ".join(f"{key}=`{value}`" for key, value in sorted(counts.items()))
            for pool, counts in sorted(by_pool.items())
        ],
        "",
        "## Recommended Pilot",
        "",
        "Start with the first batch, run the apply script with `--dry-run`, then analyze annotations before continuing to the remaining batches.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    rows = read_jsonl(ROOT / args.input)
    batches = split_annotation_batches(rows, batch_size=args.batch_size)
    output_dir = ROOT / args.output_dir

    batch_summaries: list[dict[str, object]] = []
    for index, batch in enumerate(batches, start=1):
        batch_id = f"{args.prefix}_{index:02d}"
        relative_path = f"{args.output_dir}/{batch_id}.csv".replace("\\", "/")
        write_csv(
            ROOT / relative_path,
            annotation_template_rows(batch, batch_id=batch_id),
        )
        batch_summaries.append(
            {
                "batch_id": batch_id,
                "path": relative_path,
                "rows": len(batch),
            }
        )

    payload = {
        "status": "ok",
        "input": args.input,
        "output_dir": str(output_dir.relative_to(ROOT)).replace("\\", "/"),
        "batch_size": args.batch_size,
        "batches": batch_summaries,
        "progress": annotation_progress_summary(rows),
    }
    write_json(ROOT / args.summary_output, payload)
    report_path = ensure_parent(ROOT / args.report_output)
    report_path.write_text(render_progress_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
