from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import analyze_manual_evidence_annotations
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze completed manual evidence-span annotations.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
        help="Annotated audit JSONL path.",
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_primevul_manual_evidence_audit_v1_annotation_analysis.json",
        help="Output JSON analysis path.",
    )
    parser.add_argument(
        "--report-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_ANALYSIS.md",
        help="Output Markdown analysis report path.",
    )
    return parser.parse_args()


def render_report(payload: dict[str, object], input_path: str) -> str:
    return "\n".join(
        [
            "# PrimeVul Manual Evidence Audit Analysis",
            "",
            f"- Input: `{input_path}`",
            f"- Rows: `{payload['rows']}`",
            f"- Completed annotations: `{payload['completed_annotations']}`",
            f"- Completion rate: `{payload['completion_rate']}`",
            f"- Invalid annotations: `{payload['invalid_annotations']}`",
            "",
            "This report tracks completed evidence annotations and is the primary summary for evidence-side agreement, evidence quality, and label issue rates.",
            "Annotator counts are reported explicitly so pilot/self-review rows are not confused with independent human gold annotations.",
            "",
            "## Annotator Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(payload["annotator_counts"].items())],
            "",
            "## Human vs Gold",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(payload["human_vs_gold"].items())],
            "",
            "## Evidence vs Gold",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(payload["evidence_vs_gold"].items())],
            "",
            "## Evidence Quality Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(payload["evidence_quality_counts"].items())],
            "",
            "## Label Issue Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(payload["label_issue_counts"].items())],
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    rows = read_jsonl(ROOT / args.input)
    payload = analyze_manual_evidence_annotations(rows)
    write_json(ROOT / args.output, payload)
    report_path = ensure_parent(ROOT / args.report_output)
    report_path.write_text(render_report(payload, args.input.replace("\\", "/")), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 1 if payload["invalid_annotations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
