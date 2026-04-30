from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_large_diff_windows import top_hunks
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def support_scores(hunk: dict[str, Any]) -> dict[str, int]:
    protection_delta = int(hunk["protection_delta"])
    risk_delta = int(hunk["risk_delta"])
    safer_delta = int(hunk["safer_delta"])
    risk_support = max(0, -protection_delta) + max(0, risk_delta) + max(0, -safer_delta)
    safety_support = max(0, protection_delta) + max(0, -risk_delta) + max(0, safer_delta)
    return {
        "risk_support": risk_support,
        "safety_support": safety_support,
        "net_risk_support": risk_support - safety_support,
    }


def localize_row(data: dict[str, Any], prediction: dict[str, Any], *, hunk_limit: int) -> dict[str, Any]:
    hunks = []
    for hunk in top_hunks(str(data.get("pair_text") or data.get("prompt") or ""), limit=hunk_limit):
        scores = support_scores(hunk)
        hunks.append({**hunk, **scores})
    total_risk = sum(int(hunk["risk_support"]) for hunk in hunks)
    total_safety = sum(int(hunk["safety_support"]) for hunk in hunks)
    pred = int(prediction["pred"])
    gold = int(prediction.get("gold", int(bool(data.get("has_vulnerability")))))
    if pred == 1:
        support_label = "supported" if total_risk > total_safety else "unsupported"
    else:
        support_label = "supported" if total_safety > total_risk else "unsupported"
    return {
        "id": prediction["id"],
        "pair_key": prediction.get("pair_key") or data.get("pair_key") or prediction["id"],
        "project": data.get("project", "unknown"),
        "cve": data.get("cve", "unknown"),
        "vulnerability_type": data.get("vulnerability_type", "unknown"),
        "gold": gold,
        "pred": pred,
        "correct": gold == pred,
        "vuln_probability": prediction.get("vuln_probability"),
        "pair_coupled": bool(prediction.get("pair_coupled", False)),
        "pre_coupled_pred": prediction.get("pre_coupled_pred"),
        "risk_support": total_risk,
        "safety_support": total_safety,
        "net_risk_support": total_risk - total_safety,
        "support_label": support_label,
        "top_hunks": hunks,
    }


def rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    correct = sum(1 for row in rows if row["correct"])
    supported = sum(1 for row in rows if row["support_label"] == "supported")
    supported_correct = sum(1 for row in rows if row["correct"] and row["support_label"] == "supported")
    supported_errors = sum(1 for row in rows if not row["correct"] and row["support_label"] == "supported")
    unsupported_correct = sum(1 for row in rows if row["correct"] and row["support_label"] != "supported")
    unsupported_errors = sum(1 for row in rows if not row["correct"] and row["support_label"] != "supported")
    direction_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    for row in rows:
        cwe_counts[str(row["vulnerability_type"])] += 1
        for hunk in row["top_hunks"]:
            direction_counts.update(hunk["direction_labels"])
    return {
        "rows": total,
        "unique_pair_count": len({str(row["pair_key"]) for row in rows}),
        "correct": correct,
        "errors": total - correct,
        "supported": supported,
        "unsupported": total - supported,
        "accuracy": rate(correct, total),
        "support_rate": rate(supported, total),
        "supported_correct": supported_correct,
        "supported_errors": supported_errors,
        "unsupported_correct": unsupported_correct,
        "unsupported_errors": unsupported_errors,
        "supported_error_rate": rate(supported_errors, supported),
        "unsupported_error_rate": rate(unsupported_errors, total - supported),
        "top_direction_labels": direction_counts.most_common(10),
        "top_cwes": cwe_counts.most_common(10),
    }


def build_report(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    hunk_limit: int,
    example_limit: int,
) -> dict[str, Any]:
    data_by_id = {row["id"]: row for row in dataset_rows}
    localized = [
        localize_row(data_by_id[prediction["id"]], prediction, hunk_limit=hunk_limit)
        for prediction in prediction_rows
        if prediction["id"] in data_by_id
    ]
    errors = [row for row in localized if not row["correct"]]
    unsupported = [row for row in localized if row["support_label"] != "supported"]
    high_risk_support = sorted(localized, key=lambda row: row["net_risk_support"], reverse=True)
    high_safety_support = sorted(localized, key=lambda row: row["net_risk_support"])
    return {
        "summary": summarize(localized),
        "coupled_summary": summarize([row for row in localized if row["pair_coupled"]]),
        "examples": {
            "unsupported_predictions": unsupported[:example_limit],
            "errors": errors[:example_limit],
            "highest_risk_support": high_risk_support[:example_limit],
            "highest_safety_support": high_safety_support[:example_limit],
        },
        "rows": localized,
    }


def render_hunk(hunk: dict[str, Any]) -> list[str]:
    lines = [
        (
            f"- Hunk `{hunk['header']}` risk `{hunk['risk_support']}` safety `{hunk['safety_support']}` "
            f"directions `{', '.join(hunk['direction_labels'])}`"
        )
    ]
    if hunk["removed_preview"]:
        lines.append(f"- Removed: `{' | '.join(hunk['removed_preview'])[:180]}`")
    if hunk["added_preview"]:
        lines.append(f"- Added: `{' | '.join(hunk['added_preview'])[:180]}`")
    return lines


def render_examples(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"## {title}", ""]
    for row in rows:
        lines.extend(
            [
                f"### {row['id']}",
                "",
                f"- Project/CVE/CWE: `{row['project']}` / `{row['cve']}` / `{row['vulnerability_type']}`",
                f"- Gold/Pred/Correct: `{row['gold']}` / `{row['pred']}` / `{row['correct']}`",
                f"- Probability: `{row['vuln_probability']}`",
                f"- Support: `{row['support_label']}` risk `{row['risk_support']}` safety `{row['safety_support']}` net `{row['net_risk_support']}`",
            ]
        )
        for hunk in row["top_hunks"]:
            lines.extend(render_hunk(hunk))
        lines.append("")
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    coupled = payload["coupled_summary"]
    lines = [
        "# PrimeVul Pair Evidence Localization",
        "",
        "This report adds a heuristic evidence-localization layer on top of paired diff predictions. It does not claim gold evidence-span supervision; it scores whether the selected hunks directionally support a vulnerable or safe candidate-side decision.",
        "",
        "## Summary",
        "",
        "| scope | rows | pairs | accuracy | support_rate | supported_error_rate | unsupported_error_rate |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| all rows | {summary['rows']} | {summary['unique_pair_count']} | {summary['accuracy']} | "
            f"{summary['support_rate']} | {summary['supported_error_rate']} | {summary['unsupported_error_rate']} |"
        ),
        (
            f"| pair-coupled rows | {coupled['rows']} | {coupled['unique_pair_count']} | {coupled['accuracy']} | "
            f"{coupled['support_rate']} | {coupled['supported_error_rate']} | {coupled['unsupported_error_rate']} |"
        ),
        "",
        "## Aggregate Signals",
        "",
        f"- Top direction labels: `{summary['top_direction_labels']}`",
        f"- Top CWEs: `{summary['top_cwes']}`",
        "",
        *render_examples("Unsupported Predictions", payload["examples"]["unsupported_predictions"]),
        *render_examples("Errors", payload["examples"]["errors"]),
        *render_examples("Highest Risk-Support Hunks", payload["examples"]["highest_risk_support"]),
        *render_examples("Highest Safety-Support Hunks", payload["examples"]["highest_safety_support"]),
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze heuristic evidence localization for PrimeVul paired diff predictions.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--hunk-limit", type=int, default=2)
    parser.add_argument("--example-limit", type=int, default=6)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    parser.add_argument("--rows-output")
    args = parser.parse_args()

    payload = build_report(
        read_jsonl(args.dataset),
        read_jsonl(args.predictions),
        hunk_limit=args.hunk_limit,
        example_limit=args.example_limit,
    )
    rows = payload.pop("rows")
    write_json(args.json_output, payload)
    if args.rows_output:
        write_jsonl(args.rows_output, rows)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
