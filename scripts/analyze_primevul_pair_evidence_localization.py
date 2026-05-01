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


def support_label_for_decision(*, decision: int, risk_support: int, safety_support: int) -> str:
    if decision == 1:
        return "supported" if risk_support > safety_support else "unsupported"
    return "supported" if safety_support > risk_support else "unsupported"


def localize_row(data: dict[str, Any], prediction: dict[str, Any], *, hunk_limit: int) -> dict[str, Any]:
    hunks = []
    for hunk in top_hunks(str(data.get("pair_text") or data.get("prompt") or ""), limit=hunk_limit):
        scores = support_scores(hunk)
        hunks.append({**hunk, **scores})
    total_risk = sum(int(hunk["risk_support"]) for hunk in hunks)
    total_safety = sum(int(hunk["safety_support"]) for hunk in hunks)
    pred = int(prediction["pred"])
    gold = int(prediction.get("gold", int(bool(data.get("has_vulnerability")))))
    support_label = support_label_for_decision(
        decision=pred,
        risk_support=total_risk,
        safety_support=total_safety,
    )
    gold_support_label = support_label_for_decision(
        decision=gold,
        risk_support=total_risk,
        safety_support=total_safety,
    )
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
        "gold_support_label": gold_support_label,
        "pseudo_localization_correct": gold_support_label == "supported",
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
    gold_supported = sum(1 for row in rows if row["gold_support_label"] == "supported")
    vulnerable_rows = [row for row in rows if int(row["gold"]) == 1]
    safe_rows = [row for row in rows if int(row["gold"]) == 0]
    vulnerable_gold_supported = sum(1 for row in vulnerable_rows if row["gold_support_label"] == "supported")
    safe_gold_supported = sum(1 for row in safe_rows if row["gold_support_label"] == "supported")
    direction_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    support_confusion: Counter[str] = Counter()
    for row in rows:
        cwe_counts[str(row["vulnerability_type"])] += 1
        support_confusion[f"pred_{row['support_label']}__gold_{row['gold_support_label']}"] += 1
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
        "pseudo_localization_accuracy": rate(gold_supported, total),
        "vulnerable_pseudo_localization_accuracy": rate(vulnerable_gold_supported, len(vulnerable_rows)),
        "safe_pseudo_localization_accuracy": rate(safe_gold_supported, len(safe_rows)),
        "support_confusion": dict(sorted(support_confusion.items())),
        "top_direction_labels": direction_counts.most_common(10),
        "top_cwes": cwe_counts.most_common(10),
    }


def build_report(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    hunk_limit: int,
    example_limit: int,
    sweep_hunk_limits: list[int] | None = None,
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
    report = {
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
    if sweep_hunk_limits:
        report["hunk_limit_sweep"] = hunk_limit_sweep(
            dataset_rows,
            prediction_rows,
            hunk_limits=sweep_hunk_limits,
        )
    return report


def hunk_limit_sweep(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    hunk_limits: list[int],
) -> list[dict[str, Any]]:
    data_by_id = {row["id"]: row for row in dataset_rows}
    rows: list[dict[str, Any]] = []
    for limit in hunk_limits:
        localized = [
            localize_row(data_by_id[prediction["id"]], prediction, hunk_limit=limit)
            for prediction in prediction_rows
            if prediction["id"] in data_by_id
        ]
        summary = summarize(localized)
        rows.append(
            {
                "hunk_limit": limit,
                "support_rate": summary["support_rate"],
                "pseudo_localization_accuracy": summary["pseudo_localization_accuracy"],
                "vulnerable_pseudo_localization_accuracy": summary["vulnerable_pseudo_localization_accuracy"],
                "safe_pseudo_localization_accuracy": summary["safe_pseudo_localization_accuracy"],
                "supported_error_rate": summary["supported_error_rate"],
                "unsupported_error_rate": summary["unsupported_error_rate"],
            }
        )
    return rows


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
                f"- Gold support: `{row['gold_support_label']}` pseudo-localization-correct `{row['pseudo_localization_correct']}`",
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
        "| scope | rows | pairs | accuracy | support_rate | pseudo_loc_acc | vuln_pseudo_loc | safe_pseudo_loc | supported_error_rate | unsupported_error_rate |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| all rows | {summary['rows']} | {summary['unique_pair_count']} | {summary['accuracy']} | "
            f"{summary['support_rate']} | {summary['pseudo_localization_accuracy']} | "
            f"{summary['vulnerable_pseudo_localization_accuracy']} | {summary['safe_pseudo_localization_accuracy']} | "
            f"{summary['supported_error_rate']} | {summary['unsupported_error_rate']} |"
        ),
        (
            f"| pair-coupled rows | {coupled['rows']} | {coupled['unique_pair_count']} | {coupled['accuracy']} | "
            f"{coupled['support_rate']} | {coupled['pseudo_localization_accuracy']} | "
            f"{coupled['vulnerable_pseudo_localization_accuracy']} | {coupled['safe_pseudo_localization_accuracy']} | "
            f"{coupled['supported_error_rate']} | {coupled['unsupported_error_rate']} |"
        ),
        "",
        "## Aggregate Signals",
        "",
        f"- Top direction labels: `{summary['top_direction_labels']}`",
        f"- Top CWEs: `{summary['top_cwes']}`",
        f"- Support confusion: `{summary['support_confusion']}`",
        "",
    ]
    if payload.get("hunk_limit_sweep"):
        lines.extend(
            [
                "## Hunk-Limit Sweep",
                "",
                "| hunk_limit | support_rate | pseudo_loc_acc | vuln_pseudo_loc | safe_pseudo_loc | supported_error_rate | unsupported_error_rate |",
                "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in payload["hunk_limit_sweep"]:
            lines.append(
                (
                    f"| {row['hunk_limit']} | {row['support_rate']} | {row['pseudo_localization_accuracy']} | "
                    f"{row['vulnerable_pseudo_localization_accuracy']} | {row['safe_pseudo_localization_accuracy']} | "
                    f"{row['supported_error_rate']} | {row['unsupported_error_rate']} |"
                )
            )
        lines.append("")
    lines.extend(
        [
            *render_examples("Unsupported Predictions", payload["examples"]["unsupported_predictions"]),
            *render_examples("Errors", payload["examples"]["errors"]),
            *render_examples("Highest Risk-Support Hunks", payload["examples"]["highest_risk_support"]),
            *render_examples("Highest Safety-Support Hunks", payload["examples"]["highest_safety_support"]),
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze heuristic evidence localization for PrimeVul paired diff predictions.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--hunk-limit", type=int, default=2)
    parser.add_argument("--example-limit", type=int, default=6)
    parser.add_argument("--sweep-hunk-limits", default="1,2,3,5")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    parser.add_argument("--rows-output")
    args = parser.parse_args()

    payload = build_report(
        read_jsonl(args.dataset),
        read_jsonl(args.predictions),
        hunk_limit=args.hunk_limit,
        example_limit=args.example_limit,
        sweep_hunk_limits=[int(part.strip()) for part in args.sweep_hunk_limits.split(",") if part.strip()],
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
