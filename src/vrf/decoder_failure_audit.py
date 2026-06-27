from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from vrf.relation_consistent_decoder import (
    SUPPORTED_RELATIONS,
    _canonical_probability,
    project_relation_consistent_predictions,
)
from vrf.relational_evaluation import normalize_label


LOW_MARGIN = 0.05
DISAGREEMENT_RANGE = 0.20


def _label_from_probability(probability_a: float) -> str:
    return "A" if probability_a >= 0.5 else "B"


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _prediction_label(row: dict[str, Any]) -> str:
    return normalize_label(row.get("predicted_riskier_side", row.get("prediction")))


def _is_correct(label: str, gold: str) -> bool:
    return normalize_label(label) == normalize_label(gold)


def _view_contributors(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_relation: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        relation = str(row.get("expected_relation"))
        if relation not in SUPPORTED_RELATIONS:
            continue
        value = _canonical_probability(row)
        if value is not None:
            by_relation[relation].append(value)

    return {
        "identity": _mean(by_relation.get("identity", [])),
        "invariant_mean": _mean(by_relation.get("invariant", [])),
        "invariant_values": by_relation.get("invariant", []),
        "equivariant_swap_projected_mean": _mean(
            by_relation.get("equivariant_swap", [])
        ),
        "equivariant_swap_projected_values": by_relation.get(
            "equivariant_swap", []
        ),
    }


def _canonical_values(rows: list[dict[str, Any]]) -> list[float]:
    values = []
    for row in rows:
        if str(row.get("expected_relation")) not in SUPPORTED_RELATIONS:
            continue
        value = _canonical_probability(row)
        if value is not None:
            values.append(value)
    return values


def _opposes_identity(value: float | None, identity_label: str) -> bool:
    if value is None:
        return False
    return _label_from_probability(value) != identity_label


def _likely_driver(
    *,
    identity_probability: float,
    canonical_projection: float,
    contributors: dict[str, Any],
    cross_view_range: float,
) -> str:
    identity_label = _label_from_probability(identity_probability)
    identity_margin = abs(identity_probability - 0.5)
    canonical_margin = abs(canonical_projection - 0.5)
    invariant_opposes = _opposes_identity(
        contributors["invariant_mean"], identity_label
    )
    swap_opposes = _opposes_identity(
        contributors["equivariant_swap_projected_mean"], identity_label
    )

    if identity_margin <= LOW_MARGIN and canonical_margin <= LOW_MARGIN:
        return "ambiguous_near_threshold_projection"
    if identity_margin <= LOW_MARGIN and cross_view_range >= DISAGREEMENT_RANGE:
        return "low_identity_margin"
    if invariant_opposes and swap_opposes:
        return "multi_view_majority_overrides_identity"
    if swap_opposes:
        return "swap_view_overrides_identity"
    if invariant_opposes:
        return "invariant_view_overrides_identity"
    if cross_view_range >= DISAGREEMENT_RANGE:
        return "cross_view_disagreement"
    if identity_margin <= LOW_MARGIN:
        return "low_identity_margin"
    return "multi_view_majority_overrides_identity"


def _flip_outcome(baseline_label: str, decoded_label: str, gold: str) -> str:
    before_correct = _is_correct(baseline_label, gold)
    after_correct = _is_correct(decoded_label, gold)
    if before_correct and after_correct:
        return "correct_to_correct"
    if before_correct and not after_correct:
        return "correct_to_wrong"
    if not before_correct and after_correct:
        return "wrong_to_correct"
    return "wrong_to_wrong"


def audit_decoder_identity_distortion(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    max_cases: int | None = 50,
) -> dict[str, Any]:
    """Audit identity rows changed by relation-consistent decoding.

    Gold labels are used only after decoding to audit the consequence of
    identity flips. They are never passed into the decoder or used to compute
    the projected probabilities.
    """

    prediction_by_id = {str(row["id"]): row for row in prediction_rows}
    decoded = project_relation_consistent_predictions(benchmark_rows, prediction_rows)
    decoded_by_id = {str(row["id"]): row for row in decoded["predictions"]}

    joined_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for benchmark in benchmark_rows:
        prediction = prediction_by_id[str(benchmark["id"])]
        joined_groups[str(benchmark["base_id"])].append(
            {
                **benchmark,
                "predicted_riskier_side": _prediction_label(prediction),
                "probability_a": prediction.get("probability_a"),
            }
        )

    identity_rows = [
        row
        for row in benchmark_rows
        if str(row.get("expected_relation")) == "identity"
    ]
    outcome_counts: Counter[str] = Counter()
    driver_counts: Counter[str] = Counter()
    distorted_cases: list[dict[str, Any]] = []
    flipped_toward_gold = 0
    flipped_away_from_gold = 0

    for identity in identity_rows:
        row_id = str(identity["id"])
        baseline = prediction_by_id[row_id]
        decoded_prediction = decoded_by_id[row_id]
        baseline_label = _prediction_label(baseline)
        decoded_label = _prediction_label(decoded_prediction)
        gold = normalize_label(identity["gold_riskier_side"])
        outcome = _flip_outcome(baseline_label, decoded_label, gold)
        changed = baseline_label != decoded_label

        if not changed:
            outcome_counts[f"{outcome}_unchanged"] += 1
            continue

        outcome_counts[outcome] += 1
        if outcome == "wrong_to_correct":
            flipped_toward_gold += 1
        if outcome == "correct_to_wrong":
            flipped_away_from_gold += 1

        group_rows = joined_groups[str(identity["base_id"])]
        canonical_values = _canonical_values(group_rows)
        canonical_projection = decoded_prediction.get(
            "relation_consistent_decoder", {}
        ).get("canonical_probability_a")
        if canonical_projection is None and canonical_values:
            canonical_projection = sum(canonical_values) / len(canonical_values)

        baseline_probability = float(baseline["probability_a"])
        decoded_probability = float(decoded_prediction["probability_a"])
        canonical_projection = float(canonical_projection)
        contributors = _view_contributors(group_rows)
        cross_view_range = (
            max(canonical_values) - min(canonical_values)
            if canonical_values
            else 0.0
        )
        driver = _likely_driver(
            identity_probability=baseline_probability,
            canonical_projection=canonical_projection,
            contributors=contributors,
            cross_view_range=cross_view_range,
        )
        driver_counts[driver] += 1

        distorted_cases.append(
            {
                "id": row_id,
                "pair_key": identity.get("pair_key"),
                "base_id": identity.get("base_id"),
                "dataset": identity.get("dataset"),
                "project": identity.get("project"),
                "cwe": identity.get("cwe"),
                "cve": identity.get("cve"),
                "sampling_suite": identity.get("sampling_suite"),
                "gold_riskier_side": gold,
                "baseline_prediction": baseline_label,
                "decoded_prediction": decoded_label,
                "baseline_probability_a": baseline_probability,
                "decoded_probability_a": decoded_probability,
                "identity_margin": abs(baseline_probability - 0.5),
                "canonical_projection_margin": abs(canonical_projection - 0.5),
                "cross_view_probability_range": cross_view_range,
                "view_contributors": contributors,
                "flip_outcome": outcome,
                "likely_driver": driver,
            }
        )

    distorted_cases.sort(
        key=lambda item: (
            item["flip_outcome"] != "correct_to_wrong",
            -item["identity_margin"],
            -item["cross_view_probability_range"],
            str(item["id"]),
        )
    )

    distorted_count = len(distorted_cases)
    return {
        "status": "ok",
        "inputs": {
            "benchmark_rows": len(benchmark_rows),
            "prediction_rows": len(prediction_rows),
        },
        "decoder_summary": decoded["summary"],
        "summary": {
            "identity_rows": len(identity_rows),
            "distorted_identity_rows": distorted_count,
            "identity_distortion_rate": (
                distorted_count / len(identity_rows) if identity_rows else None
            ),
            "flips_toward_gold": flipped_toward_gold,
            "flips_away_from_gold": flipped_away_from_gold,
            "flip_outcome_counts": dict(sorted(outcome_counts.items())),
            "driver_counts": dict(sorted(driver_counts.items())),
        },
        "distorted_identity_cases": (
            distorted_cases if max_cases is None else distorted_cases[:max_cases]
        ),
        "case_selection": {
            "max_cases": max_cases,
            "ordering": (
                "correct_to_wrong first, then larger identity margin, larger "
                "cross-view probability range, and stable row id"
            ),
        },
        "claim_boundary": (
            "This audit explains where the relation-consistent decoder reshapes "
            "identity predictions. Gold labels are used only after the fact to "
            "audit consequences of identity flips, not by the decoder. The audit "
            "does not change the decoder, benchmark, model, or result claims."
        ),
    }


def render_decoder_failure_audit_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Decoder Failure Case Audit",
        "",
        "## Scope",
        "",
        "This audit examines identity rows changed by the relation-consistent",
        "decoder on the retained Qwen 1.5B VeriPatch-RR smoke prediction",
        "artifact. It focuses on decoder side effects, especially identity",
        "distortion.",
        "",
        "Gold labels are used only to audit consequences of identity flips after",
        "decoding. They are not used by the decoder.",
        "",
        "This audit explains where the decoder reshapes identity predictions. It",
        "does not change the decoder, benchmark, or model.",
        "",
        "## Inputs",
        "",
        "- Benchmark: `data/processed/secure_code_relational_benchmark_v2_qwen15b_runtime.jsonl`",
        "- Predictions: `outputs/secure_code_veripatch_rr_qwen15b_smoke_predictions.jsonl`",
        "- JSON report: `reports/decoder_failure_case_audit_v1.json`",
        "",
        "## Identity Distortion Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Identity rows | {summary['identity_rows']:,} |",
        f"| Distorted identity rows | {summary['distorted_identity_rows']:,} |",
        f"| Identity distortion rate | {summary['identity_distortion_rate']:.4f} |",
        f"| Flips toward gold | {summary['flips_toward_gold']:,} |",
        f"| Flips away from gold | {summary['flips_away_from_gold']:,} |",
        "",
        "## Flip Outcome Decomposition",
        "",
        "| Outcome | Count |",
        "| --- | ---: |",
    ]
    for outcome, count in summary["flip_outcome_counts"].items():
        lines.append(f"| {outcome} | {count:,} |")

    lines.extend(
        [
            "",
            "## Driver Categories",
            "",
            "| Likely driver | Count |",
            "| --- | ---: |",
        ]
    )
    for driver, count in summary["driver_counts"].items():
        lines.append(f"| {driver} | {count:,} |")

    lines.extend(
        [
            "",
            "Driver labels are heuristics over identity margin, canonical projection",
            "margin, and cross-view probability disagreement. They are diagnostic",
            "tags, not causal proof.",
            "",
            "## Representative Failure Cases",
            "",
            "| ID | Outcome | Driver | Baseline | Decoded | Gold | Identity margin | Cross-view range |",
            "| --- | --- | --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for case in report["distorted_identity_cases"][:10]:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{case['id']}`",
                    case["flip_outcome"],
                    case["likely_driver"],
                    case["baseline_prediction"],
                    case["decoded_prediction"],
                    case["gold_riskier_side"],
                    f"{case['identity_margin']:.4f}",
                    f"{case['cross_view_probability_range']:.4f}",
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Interpretation Boundary",
            "",
            "This audit does not claim that all distorted rows are fixed or harmed by",
            "the decoder. Correctness labels are used after the fact to categorize",
            "flip consequences. The decoder itself still uses only declared expected",
            "relations and model probabilities.",
            "",
            "The audit shows where relation-consistent projection can trade identity",
            "behavior for cross-view consistency. It should be read alongside",
            "`reports/DECODER_STRESS_VALIDATION.md`, not as a standalone model quality result.",
            "",
            "This report does not claim improved model reasoning.",
            "",
        ]
    )
    return "\n".join(lines)
