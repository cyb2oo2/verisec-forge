from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_jsonl, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a pilot findings report from manual evidence annotations.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
        help="Annotated manual evidence audit JSONL.",
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_primevul_manual_evidence_pilot_findings_v1.json",
        help="Output JSON findings path.",
    )
    parser.add_argument(
        "--md-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS.md",
        help="Output Markdown findings path.",
    )
    return parser.parse_args()


def _agreement(row: dict[str, Any]) -> str:
    annotation = row.get("annotation", {})
    return "match" if annotation.get("human_vulnerable_side") == row.get("gold_vulnerable_side") else "mismatch"


def _completed_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    completed: list[dict[str, Any]] = []
    for row in rows:
        annotation = row.get("annotation", {})
        if annotation.get("human_vulnerable_side") is not None:
            completed.append(row)
    return completed


def _case_summary(row: dict[str, Any]) -> dict[str, Any]:
    annotation = row.get("annotation", {})
    return {
        "audit_id": row.get("audit_id"),
        "source_pool": row.get("source_pool"),
        "gold_vulnerable_side": row.get("gold_vulnerable_side"),
        "pilot_vulnerable_side": annotation.get("human_vulnerable_side"),
        "evidence_side": annotation.get("evidence_side"),
        "evidence_quality": annotation.get("evidence_quality"),
        "label_issue": annotation.get("label_issue"),
        "selected_window_ids": annotation.get("selected_window_ids", []),
        "notes": annotation.get("notes", ""),
    }


def build_findings(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = _completed_rows(rows)
    by_pool: dict[str, Counter[str]] = defaultdict(Counter)
    issue_by_agreement: dict[str, Counter[str]] = defaultdict(Counter)
    quality_by_agreement: dict[str, Counter[str]] = defaultdict(Counter)

    agreement_counts = Counter()
    quality_counts = Counter()
    issue_counts = Counter()
    annotator_counts = Counter()

    high_quality_disagreements: list[dict[str, Any]] = []
    insufficient_context_cases: list[dict[str, Any]] = []

    for row in completed:
        annotation = row.get("annotation", {})
        agreement = _agreement(row)
        quality = annotation.get("evidence_quality")
        issue = annotation.get("label_issue", "none")
        annotator = annotation.get("annotator") or "unknown"

        agreement_counts[agreement] += 1
        quality_counts[str(quality)] += 1
        issue_counts[issue] += 1
        annotator_counts[annotator] += 1
        by_pool[row.get("source_pool", "unknown")][agreement] += 1
        issue_by_agreement[agreement][issue] += 1
        quality_by_agreement[agreement][str(quality)] += 1

        if agreement == "mismatch" and quality in {2, 3} and issue == "none":
            high_quality_disagreements.append(_case_summary(row))
        if issue == "insufficient_context":
            insufficient_context_cases.append(_case_summary(row))

    completed_count = len(completed)
    return {
        "rows": len(rows),
        "completed_annotations": completed_count,
        "completion_rate": round(completed_count / len(rows), 4) if rows else 0.0,
        "annotator_counts": dict(sorted(annotator_counts.items())),
        "agreement_counts": dict(sorted(agreement_counts.items())),
        "agreement_rate": round(agreement_counts["match"] / completed_count, 4) if completed_count else 0.0,
        "evidence_quality_counts": dict(sorted(quality_counts.items())),
        "label_issue_counts": dict(sorted(issue_counts.items())),
        "by_source_pool": {pool: dict(sorted(counts.items())) for pool, counts in sorted(by_pool.items())},
        "issue_by_agreement": {
            key: dict(sorted(value.items()))
            for key, value in sorted(issue_by_agreement.items())
        },
        "quality_by_agreement": {
            key: dict(sorted(value.items()))
            for key, value in sorted(quality_by_agreement.items())
        },
        "high_quality_disagreement_count": len(high_quality_disagreements),
        "high_quality_disagreements": high_quality_disagreements,
        "insufficient_context_count": len(insufficient_context_cases),
        "insufficient_context_cases": insufficient_context_cases,
        "interpretation": [
            "This is a codex_pilot audit, not independent human gold.",
            "The hard side-inversion queue is evidence-noisy: pilot/gold agreement is close to balanced rather than near-certain.",
            "High-quality pilot disagreements are the most valuable adjudication targets because the visible evidence conflicts with the stored vulnerable side.",
            "Insufficient-context cases indicate where hunk windows are too narrow for reliable evidence localization.",
        ],
    }


def render_markdown(payload: dict[str, Any], input_path: str) -> str:
    high_quality = payload["high_quality_disagreements"]
    insufficient = payload["insufficient_context_cases"]
    lines = [
        "# PrimeVul Manual Evidence Pilot Findings",
        "",
        f"- Input: `{input_path}`",
        f"- Completed annotations: `{payload['completed_annotations']}/{payload['rows']}`",
        f"- Pilot/gold agreement: `{payload['agreement_counts'].get('match', 0)}` match / `{payload['agreement_counts'].get('mismatch', 0)}` mismatch",
        f"- Agreement rate: `{payload['agreement_rate']}`",
        f"- High-quality disagreements: `{payload['high_quality_disagreement_count']}`",
        f"- Insufficient-context cases: `{payload['insufficient_context_count']}`",
        "",
        "Important: this is a `codex_pilot` audit, not independent human gold. It is useful for workflow validation, case triage, and taxonomy design.",
        "",
        "## Main Takeaways",
        "",
        "- The hard side-inversion queue is not a clean confirmation set: pilot/gold agreement is close to balanced, so many examples need adjudication.",
        "- Strong evidence disagreements are more valuable than weak mismatches because they identify possible label direction conflicts or diff-pair orientation issues.",
        "- `insufficient_context` cases show that hunk/window evidence alone is sometimes too narrow, especially for helper refactors, API semantics, and error-path rewrites.",
        "- The next research step should be independent review of high-quality disagreements plus wider-context review for insufficient-context cases.",
        "",
        "## Counts",
        "",
        "### Annotators",
        "",
        *[f"- `{key}`: `{value}`" for key, value in sorted(payload["annotator_counts"].items())],
        "",
        "### Evidence Quality",
        "",
        *[f"- `{key}`: `{value}`" for key, value in sorted(payload["evidence_quality_counts"].items())],
        "",
        "### Label Issues",
        "",
        *[f"- `{key}`: `{value}`" for key, value in sorted(payload["label_issue_counts"].items())],
        "",
        "### By Source Pool",
        "",
        *[
            f"- `{pool}`: " + ", ".join(f"{key}=`{value}`" for key, value in sorted(counts.items()))
            for pool, counts in sorted(payload["by_source_pool"].items())
        ],
        "",
        "## High-Quality Disagreement Queue",
        "",
    ]
    if high_quality:
        for item in high_quality:
            lines.append(
                f"- `{item['audit_id']}`: gold=`{item['gold_vulnerable_side']}`, "
                f"pilot=`{item['pilot_vulnerable_side']}`, q=`{item['evidence_quality']}`, "
                f"windows=`{';'.join(item['selected_window_ids'])}`, note={item['notes']}"
            )
    else:
        lines.append("- None.")
    lines.extend(["", "## Insufficient-Context Queue", ""])
    if insufficient:
        for item in insufficient:
            lines.append(
                f"- `{item['audit_id']}`: gold=`{item['gold_vulnerable_side']}`, "
                f"pilot=`{item['pilot_vulnerable_side']}`, q=`{item['evidence_quality']}`, "
                f"note={item['notes']}"
            )
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    rows = read_jsonl(ROOT / args.input)
    payload = build_findings(rows)
    write_json(ROOT / args.json_output, payload)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_markdown(payload, args.input.replace("\\", "/")), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
