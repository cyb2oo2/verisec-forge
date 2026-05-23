from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.patch_review_demo import build_patch_review_demo, list_demo_examples


def _fmt_prob(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}"


def _row_summary(row: dict[str, Any]) -> dict[str, Any]:
    windows = row.get("evidence_windows", [])
    return {
        "id": row["id"],
        "decision": row["decision"],
        "gold_label": row["gold_label"],
        "correct_on_benchmark": row["correct_on_benchmark"],
        "vulnerability_probability": row.get("vulnerability_probability"),
        "support_label": row.get("support_label"),
        "risk_support": row.get("risk_support"),
        "safety_support": row.get("safety_support"),
        "top_evidence_direction": windows[0].get("direction_labels", []) if windows else [],
    }


def build_walkthrough(
    *,
    sample_id: str | None = None,
    pair_key: str | None = None,
    evidence_limit: int = 1,
    text_limit: int = 420,
) -> dict[str, Any]:
    if not sample_id and not pair_key:
        examples = list_demo_examples(limit=1)
        if not examples:
            raise ValueError("No patch-review examples are available")
        pair_key = examples[0]["pair_key"]

    payload = build_patch_review_demo(
        sample_id=sample_id,
        pair_key=pair_key,
        evidence_limit=evidence_limit,
        text_limit=text_limit,
    )
    return {
        "status": "ok",
        "walkthrough_type": "artifact_backed_external_validation_walkthrough",
        "selected_pair_key": payload["pair_key"],
        "pair_decision": payload["pair_decision"],
        "row_summaries": [_row_summary(row) for row in payload["rows"]],
        "full_payload": payload,
    }


def render_markdown(walkthrough: dict[str, Any]) -> str:
    payload = walkthrough["full_payload"]
    decision = payload["pair_decision"]
    rows = payload["rows"]
    risk_row = next((row for row in rows if row["id"] == decision["riskier_side_id"]), rows[0])
    safe_row = next((row for row in rows if row["id"] == decision["safer_side_id"]), rows[-1])

    lines = [
        "# Patch Review External-Validation Walkthrough",
        "",
        "This walkthrough shows how a reviewer can inspect one restored artifact-backed paired-diff example without running a model checkpoint. It connects the public PrimeVul reproduction bundle to the patch-review demo contract: paired diff identity, vulnerability probability, pair-coupled decision, support label, evidence window, and claim boundary.",
        "",
        "## Restore And Run",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts\\download_reproducibility_bundle.py --restore",
        ".\\.venv\\Scripts\\python.exe scripts\\reproduce_primevul_evidence_coupled.py",
        ".\\.venv\\Scripts\\python.exe -m vrf.cli patch-demo --pair-key \"{}\"".format(payload["pair_key"]),
        "```",
        "",
        "## Selected Pair",
        "",
        f"- Pair key: `{payload['pair_key']}`",
        f"- Riskier side: `{decision['riskier_side_id']}`",
        f"- Safer side: `{decision['safer_side_id']}`",
        f"- Probability gap: `{_fmt_prob(decision['probability_gap'])}`",
        f"- Pair-coupled decoding applied: `{str(decision['pair_coupled']).lower()}`",
        "",
        "## Side Summary",
        "",
        "| Side | ID | Decision | Gold label | Probability | Support | Risk / safety support | Benchmark correctness |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for side, row in [("Riskier", risk_row), ("Safer", safe_row)]:
        lines.append(
            f"| {side} | `{row['id']}` | `{row['decision']}` | `{row['gold_label']}` | `{_fmt_prob(row.get('vulnerability_probability'))}` | `{row.get('support_label')}` | `{row.get('risk_support')}` / `{row.get('safety_support')}` | `{str(row.get('correct_on_benchmark')).lower()}` |"
        )

    lines.extend(
        [
            "",
            "## Top Evidence Windows",
            "",
        ]
    )
    for row in [risk_row, safe_row]:
        lines.append(f"### `{row['id']}`: `{row['decision']}`")
        if not row.get("evidence_windows"):
            lines.append("")
            lines.append("No evidence window was materialized for this row.")
            lines.append("")
            continue
        window = row["evidence_windows"][0]
        lines.extend(
            [
                "",
                f"- Direction labels: `{', '.join(window.get('direction_labels', [])) or 'none'}`",
                f"- Risk support: `{window.get('risk_support')}`",
                f"- Safety support: `{window.get('safety_support')}`",
                f"- Hunk: `{window.get('header', '')}`",
                "",
                "Removed:",
                "",
                "```diff",
                window.get("removed", ""),
                "```",
                "",
                "Added:",
                "",
                "```diff",
                window.get("added", ""),
                "```",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation Boundary",
            "",
            "- This is an artifact-backed walkthrough over reproduced PrimeVul paired examples, not arbitrary online vulnerability scanning.",
            "- The pair-coupled decision shows how the system uses paired task structure; it should be read together with the statistics in `reports/FINAL_SUBMISSION_STATISTICS.md`.",
            "- Evidence windows are pseudo-localization/failure-triage artifacts. They are useful for review orientation, but they are not independent human gold labels.",
            "- Source-aware routing is summarized in the external-generalization reports and final statistics table; this PrimeVul walkthrough focuses on the evidence-coupled paired-review path.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an artifact-backed patch-review walkthrough.")
    parser.add_argument("--sample-id")
    parser.add_argument("--pair-key")
    parser.add_argument("--evidence-limit", type=int, default=1)
    parser.add_argument("--text-limit", type=int, default=420)
    parser.add_argument("--output-md", default="docs/PATCH_REVIEW_WALKTHROUGH.md")
    parser.add_argument("--output-json", default="reports/PATCH_REVIEW_WALKTHROUGH.json")
    args = parser.parse_args()

    walkthrough = build_walkthrough(
        sample_id=args.sample_id,
        pair_key=args.pair_key,
        evidence_limit=args.evidence_limit,
        text_limit=args.text_limit,
    )
    md_path = ROOT / args.output_md
    json_path = ROOT / args.output_json
    md_path.write_text(render_markdown(walkthrough), encoding="utf-8")
    json_path.write_text(json.dumps(walkthrough, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "markdown": args.output_md, "json": args.output_json}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
