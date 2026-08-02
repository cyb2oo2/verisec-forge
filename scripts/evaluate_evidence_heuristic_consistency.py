"""Report evidence analysis with the circular target removed.

Two things used to be conflated under the name "evidence localization":

1. A *heuristic consistency* computation, whose target
   (``support_label_for_decision``) is antisymmetric in the predicted side. The
   side-correct / side-wrong contrast it produced was an identity of that
   function. It is reported here under its accurate name and explicitly marked
   as non-evidential.

2. A genuine *human-grounded* evidence check, which is possible only on the
   small adjudicated audit set, where a reviewer recorded which windows
   actually contain the vulnerability. That target never sees the model's side
   prediction.

Usage::

    python scripts/evaluate_evidence_heuristic_consistency.py \
        --json-output reports/secure_code_primevul_evidence_heuristic_consistency_v1.json \
        --md-output reports/PRIMEVUL_EVIDENCE_HEURISTIC_CONSISTENCY.md
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from vrf.evidence_targets import (  # noqa: E402
    evidence_polarity_label,
    human_evidence_is_usable,
    human_evidence_windows,
    is_decision_invariant,
    normalize_window_ids,
)
from vrf.io_utils import read_jsonl, write_json  # noqa: E402
from vrf.stats_cluster import wilson_interval  # noqa: E402

ADJUDICATED_SOURCES = [
    "data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl",
    "data/processed/secure_code_primevul_manual_evidence_round2_adjudicated_v1.jsonl",
    "data/processed/secure_code_primevul_manual_evidence_insufficient_context_ai_adjudicated_v1.jsonl",
]


def circularity_audit() -> dict[str, Any]:
    from scripts.analyze_primevul_pair_evidence_localization import support_label_for_decision

    legacy_invariant = is_decision_invariant(support_label_for_decision)
    replacement_invariant = is_decision_invariant(evidence_polarity_label)
    return {
        "legacy_target": "scripts/analyze_primevul_pair_evidence_localization.support_label_for_decision",
        "legacy_target_is_decision_invariant": legacy_invariant,
        "legacy_target_verdict": (
            "INVALID as evidence ground truth: flipping the predicted side deterministically "
            "flips the target whenever risk_support != safety_support."
            if not legacy_invariant
            else "invariant"
        ),
        "replacement_target": "vrf.evidence_targets.evidence_polarity_label",
        "replacement_target_is_decision_invariant": replacement_invariant,
        "role_separation": {
            "side_prediction": "model output (pair-coupled or raw detector)",
            "evidence_scoring": "model output (hunk/window ranker)",
            "evidence_ground_truth": "human adjudication only; never derived from a model decision",
        },
    }


def load_adjudicated(paths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for relative in paths:
        path = REPO_ROOT / relative
        if not path.exists():
            continue
        for row in read_jsonl(str(path)):
            audit_id = str(row.get("audit_id"))
            if audit_id in seen:
                continue
            seen.add(audit_id)
            row["_source_file"] = relative
            rows.append(row)
    return rows


def human_grounded_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"status": "unavailable", "reason": "no adjudicated audit rows found"}

    reviewers = collections.Counter()
    statuses = collections.Counter()
    usable: list[dict[str, Any]] = []
    for row in rows:
        adjudication = row.get("adjudication") or {}
        reviewers[str(adjudication.get("reviewer", "unknown"))] += 1
        statuses[str(adjudication.get("label_status", "unknown"))] += 1
        if human_evidence_is_usable(row):
            usable.append(row)

    hits = 0
    subset_of_proposal = 0
    selected_outside_proposal = 0
    for row in usable:
        truth = human_evidence_windows(row) or frozenset()
        proposed = normalize_window_ids(row.get("selected_window_ids"))
        if truth & proposed:
            hits += 1
        if truth <= proposed:
            subset_of_proposal += 1
        if truth - proposed:
            selected_outside_proposal += 1

    # If the adjudicator never chose a window the pipeline had not already
    # proposed, the adjudication is a *constrained confirmation* of the
    # pipeline's own output. An overlap metric computed against it cannot
    # register a miss, so its value carries no information about localization.
    anchored = bool(usable) and selected_outside_proposal == 0
    interval = wilson_interval(hits, len(usable)) if usable else None
    return {
        "status": "anchored_confirmation_only" if anchored else "available_but_small",
        "adjudicated_rows": len(rows),
        "rows_with_usable_evidence_span": len(usable),
        "rows_excluded_insufficient_context": len(rows) - len(usable),
        "pipeline_window_overlaps_adjudicated_window": hits,
        "overlap_rate": round(hits / len(usable), 4) if usable else None,
        "overlap_rate_95_ci": interval,
        "adjudicated_windows_subset_of_pipeline_proposal": subset_of_proposal,
        "adjudicator_selected_window_outside_proposal": selected_outside_proposal,
        "target_is_anchored_on_pipeline_output": anchored,
        "overlap_metric_is_informative": not anchored,
        "label_status_counts": dict(statuses),
        "reviewer_counts": dict(reviewers),
        "limitations": [
            "The adjudicator only ever selected windows the pipeline had already proposed "
            f"({subset_of_proposal}/{len(usable)} subset, {selected_outside_proposal} outside). "
            "The overlap metric therefore cannot record a miss and must not be read as localization accuracy.",
            "Single adjudicating reviewer; no inter-annotator agreement is established on these final labels.",
            "Several rows were AI-drafted and then human-confirmed rather than independently annotated.",
            "Only 10 of 30 adjudicated rows carry a usable evidence span; 20 were ruled insufficient_context.",
            "No independent, pipeline-blind evidence ground truth exists in this repository today.",
        ],
    }


def build_report() -> dict[str, Any]:
    adjudicated = load_adjudicated(ADJUDICATED_SOURCES)
    return {
        "scope": "primevul_evidence_heuristic_consistency",
        "supersedes": "reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md (side-correct vs side-wrong contrast)",
        "circularity_audit": circularity_audit(),
        "human_grounded_check": human_grounded_block(adjudicated),
        "withdrawn_claim": {
            "previous": "Evidence quality depends on correct side choice: side-correct top-1 0.7610, side-wrong top-1 0.0632.",
            "status": "withdrawn",
            "reason": (
                "The target is antisymmetric in the predicted side, so the contrast is forced by the "
                "labelling function. No model evidence output enters the target."
            ),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    audit = report["circularity_audit"]
    human = report["human_grounded_check"]
    withdrawn = report["withdrawn_claim"]
    lines = [
        "# PrimeVul Evidence: Heuristic Consistency and Human-Grounded Check",
        "",
        "Generated by `scripts/evaluate_evidence_heuristic_consistency.py`.",
        "",
        f"Supersedes: `{report['supersedes']}`",
        "",
        "## Withdrawn claim",
        "",
        f"> {withdrawn['previous']}",
        "",
        f"**Status: {withdrawn['status']}.** {withdrawn['reason']}",
        "",
        "## Why the old target was invalid",
        "",
        "| property | value |",
        "| --- | --- |",
        f"| legacy target | `{audit['legacy_target']}` |",
        f"| legacy target ignores the decision | `{audit['legacy_target_is_decision_invariant']}` |",
        f"| replacement target | `{audit['replacement_target']}` |",
        f"| replacement target ignores the decision | `{audit['replacement_target_is_decision_invariant']}` |",
        "",
        audit["legacy_target_verdict"],
        "",
        "## Role separation now enforced",
        "",
        "| role | source |",
        "| --- | --- |",
    ]
    for role, source in audit["role_separation"].items():
        lines.append(f"| `{role}` | {source} |")

    lines.extend(["", "## Human-grounded evidence check", ""])
    if human.get("status") == "unavailable":
        lines.append(f"Unavailable: {human.get('reason')}.")
    else:
        rate = human["overlap_rate"]
        interval = human["overlap_rate_95_ci"]
        if human.get("target_is_anchored_on_pipeline_output"):
            lines.extend(
                [
                    "> **This check is currently non-informative.** The adjudicator selected evidence",
                    "> windows only from the set the pipeline had already proposed "
                    f"(`{human['adjudicated_windows_subset_of_pipeline_proposal']}/"
                    f"{human['rows_with_usable_evidence_span']}` subset; "
                    f"`{human['adjudicator_selected_window_outside_proposal']}` outside). A metric scored",
                    "> against an anchored target cannot record a miss, so the overlap rate below is",
                    "> structurally near-fixed and must not be cited as localization accuracy.",
                    "> Obtaining an independent, pipeline-blind annotation pass is the open work item.",
                    "",
                ]
            )
        lines.extend(
            [
                "This is the only evidence measurement whose target is not derived from a model",
                "*decision*. It is a **sanity check, not a benchmark**: the sample is tiny,",
                "single-annotator, and (see above) anchored on the pipeline's own proposal.",
                "",
                "| quantity | value |",
                "| --- | ---: |",
                f"| adjudicated rows | `{human['adjudicated_rows']}` |",
                f"| rows with a usable adjudicated evidence span | `{human['rows_with_usable_evidence_span']}` |",
                f"| rows excluded as `insufficient_context` | `{human['rows_excluded_insufficient_context']}` |",
                f"| pipeline window overlaps adjudicated window | `{human['pipeline_window_overlaps_adjudicated_window']}` |",
                f"| overlap rate | `{rate}` |",
                f"| 95% CI (Wilson) | `[{interval['low']}, {interval['high']}]` |"
                if interval
                else "| 95% CI | n/a |",
                "",
                "### Limitations",
                "",
            ]
        )
        for item in human["limitations"]:
            lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Status of the pseudo-label computation",
            "",
            "The former hunk pseudo-label pipeline is retained only as a **heuristic",
            "consistency** measurement: it describes how often a keyword-delta heuristic",
            "agrees with a decision. It is not localization accuracy, it is not",
            "human-grounded, and it must not be cited as evidence that the system explains",
            "its decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report evidence analysis without the circular target.")
    parser.add_argument("--json-output", default="reports/secure_code_primevul_evidence_heuristic_consistency_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_EVIDENCE_HEURISTIC_CONSISTENCY.md")
    args = parser.parse_args()

    report = build_report()
    write_json(str(REPO_ROOT / args.json_output), report)
    (REPO_ROOT / args.md_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
