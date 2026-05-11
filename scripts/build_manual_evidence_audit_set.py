from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import DEFAULT_REVIEW_QUEUE_PATHS, build_manual_evidence_audit_set
from vrf.io_utils import ensure_parent, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a manual evidence-span audit set from PrimeVul side-inversion review queues.",
    )
    parser.add_argument(
        "--input",
        action="append",
        dest="inputs",
        help="Review queue JSONL path. Repeat to combine queues. Defaults to the four committed queue variants.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
        help="Output JSONL path for annotation rows.",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_manual_evidence_audit_v1_summary.json",
        help="Output JSON summary path.",
    )
    parser.add_argument(
        "--report-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md",
        help="Output Markdown report path.",
    )
    parser.add_argument("--sample-size", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def render_report(summary: dict[str, object]) -> str:
    requested = summary.get("requested_sample_size")
    rows = summary["rows"]
    total = summary["total_candidates"]
    unique = summary["unique_pair_keys"]
    pool_counts = summary["pool_counts"]
    gold_counts = summary["gold_vulnerable_side_counts"]
    inversion_counts = summary["true_inversion_candidate_counts"]
    return "\n".join(
        [
            "# PrimeVul Manual Evidence Audit Set",
            "",
            "This report summarizes the first manual evidence-span audit target for the evidence-coupled paired-diff line.",
            "",
            "## Summary",
            "",
            f"- Requested sample size: `{requested}`",
            f"- Materialized rows: `{rows}`",
            f"- Total candidate rows before pair-key deduplication: `{total}`",
            f"- Unique pair keys: `{unique}`",
            f"- Output dataset: `{summary['output_path']}`",
            "",
            "The materialized count can be smaller than the requested size because the current top-k side-inversion pools contain overlapping pair keys. This is a useful diagnostic: the first audit pool is intentionally high-signal but still small.",
            "",
            "## Pool Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(pool_counts.items())],
            "",
            "## Gold Vulnerable Side Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(gold_counts.items())],
            "",
            "## True Inversion Candidate Counts",
            "",
            *[f"- `{key}`: `{value}`" for key, value in sorted(inversion_counts.items())],
            "",
            "## Annotation Contract",
            "",
            "- `human_vulnerable_side`: `A`, `B`, or `unclear`.",
            "- `evidence_side`: side supported by the selected evidence: `A`, `B`, `both`, `none`, or `unclear`.",
            "- `evidence_quality`: `0` no usable evidence, `1` weak hint, `2` plausible evidence, `3` strong direct evidence.",
            "- `selected_window_ids`: window IDs such as `A1`, `A2`, `B1` that justify the judgment.",
            "- `label_issue`: `none`, `ambiguous`, `wrong_label`, or `insufficient_context`.",
            "- `notes`: short free-text rationale.",
            "",
            "## Intended Use",
            "",
            "This audit set should be used to validate whether pseudo evidence windows actually support the vulnerable/fixed side decision. It is not a new benchmark score yet; it is the bridge from pseudo-label localization to human-checked evidence grounding.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    inputs = args.inputs or DEFAULT_REVIEW_QUEUE_PATHS
    payload = build_manual_evidence_audit_set(
        input_paths=[ROOT / path for path in inputs],
        output_path=ROOT / args.output,
        sample_size=args.sample_size,
        seed=args.seed,
    )
    payload["output_path"] = args.output.replace("\\", "/")
    payload["requested_sample_size"] = args.sample_size
    write_json(ROOT / args.summary_output, payload)
    report_path = ensure_parent(ROOT / args.report_output)
    report_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
