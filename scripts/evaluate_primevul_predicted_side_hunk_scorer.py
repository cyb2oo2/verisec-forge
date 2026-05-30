from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.train_primevul_hunk_linear_scorer import evaluate, score_rows
from vrf.io_utils import read_json, read_jsonl, write_json, write_jsonl


def parse_ints(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def prediction_by_id(predictions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in predictions}


def attach_decision_side(
    candidate_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    prediction_key: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    attached: list[dict[str, Any]] = []
    missing_source_ids: set[str] = set()
    source_ids: set[str] = set()
    correct_source_ids: set[str] = set()
    wrong_source_ids: set[str] = set()
    for row in candidate_rows:
        source_id = str(row["source_id"])
        prediction = predictions.get(source_id)
        if prediction is None:
            missing_source_ids.add(source_id)
            continue
        decision_side = int(prediction[prediction_key])
        gold = int(row["gold"])
        source_ids.add(source_id)
        if decision_side == gold:
            correct_source_ids.add(source_id)
        else:
            wrong_source_ids.add(source_id)
        attached.append(
            {
                **row,
                "decision_side": decision_side,
                "predicted_side_correct": decision_side == gold,
                "prediction_key": prediction_key,
                "prediction_vuln_probability": prediction.get("vuln_probability"),
                "prediction_pair_coupled": bool(prediction.get("pair_coupled", False)),
            }
        )
    total_sources = len(source_ids)
    return attached, {
        "prediction_key": prediction_key,
        "matched_source_count": total_sources,
        "matched_candidate_rows": len(attached),
        "missing_source_count": len(missing_source_ids),
        "decision_side_accuracy": round(len(correct_source_ids) / total_sources, 4) if total_sources else 0.0,
        "correct_source_count": len(correct_source_ids),
        "wrong_source_count": len(wrong_source_ids),
    }


def filter_by_source_correctness(rows: list[dict[str, Any]], *, correct: bool) -> list[dict[str, Any]]:
    return [row for row in rows if bool(row.get("predicted_side_correct")) is correct]


def coverage_bundle(rows: list[dict[str, Any]], *, k_values: list[int], score_key: str) -> list[dict[str, Any]]:
    if not rows:
        return []
    return evaluate(rows, k_values=k_values, score_key=score_key)


def build_report(
    candidate_rows: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    scorer_report: dict[str, Any],
    *,
    k_values: list[int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    weights = scorer_report["side_aware_weights"]
    prediction_lookup = prediction_by_id(predictions)

    oracle_rows = score_rows(candidate_rows, weights, side_aware=True, score_prefix="oracle_side_aware")
    paired_rows, paired_summary = attach_decision_side(candidate_rows, prediction_lookup, prediction_key="pred")
    pre_rows, pre_summary = attach_decision_side(candidate_rows, prediction_lookup, prediction_key="pre_coupled_pred")
    matched_source_ids = {str(row["source_id"]) for row in paired_rows}
    oracle_matched_rows = [row for row in oracle_rows if str(row["source_id"]) in matched_source_ids]

    scored_paired = score_rows(paired_rows, weights, side_aware=True, score_prefix="predicted_side_aware")
    scored_pre = score_rows(pre_rows, weights, side_aware=True, score_prefix="pre_coupled_side_aware")

    report = {
        "config": {
            "k_values": k_values,
            "candidate_rows": len(candidate_rows),
            "prediction_rows": len(predictions),
        },
        "side_source": {
            "oracle": {
                "description": "uses gold side from pseudo-label rows; diagnostic upper bound",
                "matched_source_count": len({str(row["source_id"]) for row in candidate_rows}),
                "matched_candidate_rows": len(candidate_rows),
            },
            "pair_coupled_pred": paired_summary,
            "pre_coupled_pred": pre_summary,
        },
        "coverage": {
            "oracle_side_aware_all": coverage_bundle(
                oracle_rows,
                k_values=k_values,
                score_key="oracle_side_aware_score",
            ),
            "oracle_side_aware_matched": coverage_bundle(
                oracle_matched_rows,
                k_values=k_values,
                score_key="oracle_side_aware_score",
            ),
            "pair_coupled_predicted_side": coverage_bundle(
                scored_paired,
                k_values=k_values,
                score_key="predicted_side_aware_score",
            ),
            "pre_coupled_predicted_side": coverage_bundle(
                scored_pre,
                k_values=k_values,
                score_key="pre_coupled_side_aware_score",
            ),
            "pair_coupled_predicted_side_correct_only": coverage_bundle(
                filter_by_source_correctness(scored_paired, correct=True),
                k_values=k_values,
                score_key="predicted_side_aware_score",
            ),
            "pair_coupled_predicted_side_wrong_only": coverage_bundle(
                filter_by_source_correctness(scored_paired, correct=False),
                k_values=k_values,
                score_key="predicted_side_aware_score",
            ),
        },
    }
    return report, scored_paired


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Predicted-Side Hunk Scorer",
        "",
        "This report turns the side-aware hunk+window scorer from an oracle diagnostic into an end-to-end propagation check. The scorer is still trained on pseudo labels, but eval-time feature alignment uses the pair-coupled predicted side instead of the gold side.",
        "",
        "## Side Source",
        "",
        "| side source | matched sources | matched rows | side accuracy | missing sources |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in ["oracle", "pair_coupled_pred", "pre_coupled_pred"]:
        summary = report["side_source"][name]
        lines.append(
            "| "
            + " | ".join(
                [
                    name,
                    str(summary.get("matched_source_count", "")),
                    str(summary.get("matched_candidate_rows", "")),
                    str(summary.get("decision_side_accuracy", "n/a")),
                    str(summary.get("missing_source_count", "n/a")),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Top-K Coverage",
            "",
            "| scorer | k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for scorer_name, rows in report["coverage"].items():
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        scorer_name,
                        str(row["k"]),
                        str(row["coverage"]),
                        str(row["vulnerable_coverage"]),
                        str(row["safe_coverage"]),
                        str(row["covered_rows"]),
                        str(row["rows"]),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The oracle side-aware score is an upper bound because it aligns evidence to the known target side. The pair-coupled predicted-side score is the deployment-facing diagnostic: any gap between these rows measures error propagation from the detector/pair-coupling layer into evidence localization.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate hunk+window localizer coverage with pair-coupled predicted sides.")
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--scorer-report", required=True)
    parser.add_argument("--k-values", default="1,2,3,5,8")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--scored-output")
    args = parser.parse_args()

    report, scored_rows = build_report(
        read_jsonl(args.candidates),
        read_jsonl(args.predictions),
        read_json(args.scorer_report),
        k_values=parse_ints(args.k_values),
    )
    write_json(args.json_output, report)
    if args.md_output:
        Path(args.md_output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md_output).write_text(render_markdown(report), encoding="utf-8")
    if args.scored_output:
        write_jsonl(args.scored_output, scored_rows)
    print(json.dumps(report["coverage"], indent=2))


if __name__ == "__main__":
    main()
