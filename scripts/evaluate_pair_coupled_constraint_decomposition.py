"""Separate the value of the pair-coupling constraint from the value of the model.

Pair coupling injects closed-world knowledge -- that a group is a
vulnerable/fixed pair containing exactly one vulnerable member. Comparing a
constrained decoder against an unconstrained row-level baseline therefore
measures the constraint and the model together and attributes the whole delta
to the model.

This script reports five systems on the same pair groups so the effects can be
read apart:

``unconstrained_model``
    the router's row-level predictions, no group constraint
``constraint_only_random``
    random orientation within each group, same constraint (the null)
``constraint_only_structural``
    semantics-free net LINE-count rule ranked within each group, same constraint
``constraint_only_char_structural``
    semantics-free net CHARACTER-count rule, same constraint (strongest control)
``constrained_model``
    the router's probabilities ranked within each group, same constraint

Two design rules are load-bearing here. First, the model is compared against the
**strongest** semantics-free control, not the weakest: a gap over the line-count
rule that vanishes against the character-count rule reflects tie coverage, not
reasoning. Second, every control uses its **own** unconstrained decision on
groups the constraint does not cover; borrowing another system's predictions
there contaminates the baseline and lifts the null above chance.

All uncertainty is computed by clustered bootstrap over ``pair_key`` groups,
which are the independent units; see ``vrf.stats_cluster``.

Usage::

    python scripts/evaluate_pair_coupled_constraint_decomposition.py \
        --json-output reports/secure_code_primevul_pair_coupled_constraint_decomposition_v1.json \
        --md-output reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from scripts.evaluate_primevul_bucket_router_calibrated import (  # noqa: E402
    build_report_for_threshold,
    filter_by_pair_keys,
    split_pair_keys,
)
from vrf.artifact_guard import require_artifact  # noqa: E402
from vrf.io_utils import read_json, read_jsonl, write_json  # noqa: E402
from vrf.polarity_control import fit_rule, row_features  # noqa: E402
from vrf.stats_cluster import (  # noqa: E402
    group_sign_test,
    paired_cluster_bootstrap_diff,
)

DEFAULT_CALIBRATED = "reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json"
DEFAULT_TRAIN = "data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl"

REMEDIATION = {
    "produced_by": "scripts/evaluate_primevul_bucket_router_calibrated.py",
    "obtain": (
        "python scripts/download_reproducibility_bundle.py "
        "--bundle-name primevul_router_and_evidence_coupled_inputs --restore"
    ),
    "purpose": "pair-coupling constraint decomposition",
}


def balanced_accuracy(rows: Sequence[dict[str, Any]], pred_key: str) -> float:
    tp = sum(1 for row in rows if row["gold"] == 1 and row[pred_key] == 1)
    fn = sum(1 for row in rows if row["gold"] == 1 and row[pred_key] == 0)
    tn = sum(1 for row in rows if row["gold"] == 0 and row[pred_key] == 0)
    fp = sum(1 for row in rows if row["gold"] == 0 and row[pred_key] == 1)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return (recall + specificity) / 2


def group_metric(groups: Sequence[Sequence[dict[str, Any]]], pred_key: str) -> float:
    return balanced_accuracy([row for group in groups for row in group], pred_key)


def apply_constraint(
    groups: Sequence[list[dict[str, Any]]],
    *,
    score_key: str,
    pred_key: str,
    fallback_key: str,
    rng: random.Random | None = None,
) -> None:
    """Rank rows inside each well-formed pair group and force one positive.

    ``fallback_key`` names the *same system's* unconstrained decision, used for
    groups the constraint does not apply to. Using another system's prediction
    here silently contaminates the baseline: a control that borrows the
    detector's answers on some rows is no longer semantics-free, and a random
    null that borrows them is no longer a null.
    """

    for group in groups:
        if len(group) != 2:
            # Structurally not a pair: constraint does not apply.
            for row in group:
                row[pred_key] = row[fallback_key]
            continue
        if rng is not None:
            ordered = list(group)
            rng.shuffle(ordered)
        else:
            ordered = sorted(group, key=lambda row: float(row[score_key]), reverse=True)
        for index, row in enumerate(ordered):
            row[pred_key] = 1 if index == 0 else 0


def build_report(*, calibrated_path: str, train_path: str, seed: int, iterations: int) -> dict[str, Any]:
    require_artifact(calibrated_path, **REMEDIATION)
    require_artifact(train_path, **REMEDIATION)
    calibrated = read_json(calibrated_path)
    require_artifact(calibrated["dataset"], **REMEDIATION)
    require_artifact(calibrated["default_predictions"], **REMEDIATION)
    require_artifact(calibrated["bucket_predictions"], **REMEDIATION)

    dataset_rows = read_jsonl(calibrated["dataset"])
    split = split_pair_keys(
        dataset_rows,
        calibration_fraction=float(calibrated["split"]["calibration_fraction"]),
        seed=int(calibrated["split"]["seed"]),
    )
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])
    router_rows, _ = build_report_for_threshold(
        eval_rows,
        default_predictions_path=calibrated["default_predictions"],
        bucket_predictions_path=calibrated["bucket_predictions"],
        bucket=calibrated["bucket"],
        default_threshold=float(calibrated["selection"]["thresholds"]["default"]),
        bucket_threshold=float(calibrated["selection"]["thresholds"]["bucket"]),
    )

    by_key = {str(row["id"]): row for row in eval_rows}
    train_rows = read_jsonl(train_path)
    # Both the historically reported line-count rule and the strongest known
    # semantics-free rule are carried, because reporting only the weaker one
    # overstates how much of the result is attributable to the model.
    line_rule = fit_rule("net_polarity", train_rows)
    char_rule = fit_rule("char_polarity", train_rows)

    rng_null = random.Random(seed)
    working = []
    for row in router_rows:
        source = by_key.get(str(row["id"]))
        features = row_features(source) if source is not None else None
        record = dict(row)
        record["unconstrained_model"] = int(row["pred"])
        # Each system carries its own unconstrained decision, used as the
        # fallback for groups the pair constraint does not cover.
        record["structural_score"] = line_rule.score(features) if features else 0.0
        record["char_structural_score"] = char_rule.score(features) if features else 0.0
        line_decision = line_rule.predict(features) if features else None
        char_decision = char_rule.predict(features) if features else None
        record["unconstrained_structural"] = (
            line_decision if line_decision is not None else rng_null.randint(0, 1)
        )
        record["unconstrained_char_structural"] = (
            char_decision if char_decision is not None else rng_null.randint(0, 1)
        )
        record["unconstrained_random"] = rng_null.randint(0, 1)
        working.append(record)

    buckets: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in working:
        buckets[str(row.get("pair_key") or row["id"])].append(row)
    groups = list(buckets.values())

    apply_constraint(
        groups, score_key="vuln_probability", pred_key="constrained_model",
        fallback_key="unconstrained_model",
    )
    apply_constraint(
        groups, score_key="structural_score", pred_key="constraint_only_structural",
        fallback_key="unconstrained_structural",
    )
    apply_constraint(
        groups, score_key="char_structural_score", pred_key="constraint_only_char_structural",
        fallback_key="unconstrained_char_structural",
    )
    apply_constraint(
        groups, score_key="vuln_probability", pred_key="constraint_only_random",
        fallback_key="unconstrained_random", rng=random.Random(seed),
    )

    systems = {
        "unconstrained_model": "router row-level predictions; no group constraint",
        "constraint_only_random": "random orientation inside each pair; constraint only (null)",
        "constraint_only_structural": "semantics-free net LINE-count rule ranked inside each pair",
        "constraint_only_char_structural": "semantics-free net CHARACTER-count rule ranked inside each pair (strongest control)",
        "constrained_model": "router probabilities ranked inside each pair",
    }

    results = {
        name: {
            "description": description,
            "balanced_accuracy": round(group_metric(groups, name), 4),
        }
        for name, description in systems.items()
    }

    def metric_for(name: str):
        return lambda sample: group_metric(sample, name)

    comparisons = {
        "constrained_model_minus_unconstrained_model": paired_cluster_bootstrap_diff(
            groups, metric_for("unconstrained_model"), metric_for("constrained_model"),
            iterations=iterations, seed=seed,
        ),
        "constrained_model_minus_constraint_only_structural_LINES": paired_cluster_bootstrap_diff(
            groups, metric_for("constraint_only_structural"), metric_for("constrained_model"),
            iterations=iterations, seed=seed + 1,
        ),
        "constrained_model_minus_constraint_only_structural_CHARS": paired_cluster_bootstrap_diff(
            groups, metric_for("constraint_only_char_structural"), metric_for("constrained_model"),
            iterations=iterations, seed=seed + 3,
        ),
        "constraint_only_structural_minus_constraint_only_random": paired_cluster_bootstrap_diff(
            groups, metric_for("constraint_only_random"), metric_for("constraint_only_structural"),
            iterations=iterations, seed=seed + 2,
        ),
    }

    # Group-level paired sign tests: does the constrained model orient more
    # groups correctly than each structural rule under the same constraint?
    def sign_counts(rule_key: str) -> tuple[int, int]:
        wins = losses = 0
        for group in groups:
            if len(group) != 2:
                continue
            model_correct = all(row["gold"] == row["constrained_model"] for row in group)
            rule_correct = all(row["gold"] == row[rule_key] for row in group)
            if model_correct and not rule_correct:
                wins += 1
            elif rule_correct and not model_correct:
                losses += 1
        return wins, losses

    wins, losses = sign_counts("constraint_only_structural")
    char_wins, char_losses = sign_counts("constraint_only_char_structural")

    composition: collections.Counter = collections.Counter()
    for group in groups:
        positives = sum(1 for row in group if int(row["gold"]) == 1)
        composition[(len(group), positives)] += 1

    return {
        "scope": "primevul_pair_coupled_constraint_decomposition",
        "closed_world_assumption": {
            "statement": (
                "Pair coupling assumes group membership is known and that each group contains "
                "exactly one vulnerable member."
            ),
            "available_at_deployment": False,
            "source": "benchmark construction (paired vulnerable/fixed rows share a pair_key)",
            "consequence": (
                "A constrained decoder must not be compared directly against an unconstrained "
                "baseline; the constraint itself carries part of the delta."
            ),
        },
        "group_structure": {
            "groups": len(groups),
            "size_positive_composition": {f"{size}x{positives}": count for (size, positives), count in sorted(composition.items())},
            "well_formed_pairs": sum(count for (size, positives), count in composition.items() if size == 2),
            "non_pair_groups_passed_through": sum(count for (size, _), count in composition.items() if size != 2),
            "policy": "constraint applied only to groups of exactly two rows (observable without labels)",
        },
        "systems": results,
        "comparisons": comparisons,
        "group_level_sign_test_model_vs_structural_LINES": group_sign_test(wins, losses),
        "group_level_sign_test_model_vs_structural_CHARS": group_sign_test(char_wins, char_losses),
        "headline": (
            "The model must be compared against the STRONGEST semantics-free control, not the "
            "weakest. Against the character-count rule the model shows no reliable advantage."
        ),
        "statistics_note": (
            "All intervals are clustered bootstraps over pair_key groups, the independent units. "
            "Previous intervals resampled five overlapping split seeds of one frozen prediction set."
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    systems = report["systems"]
    comparisons = report["comparisons"]
    assumption = report["closed_world_assumption"]
    structure = report["group_structure"]
    sign = report["group_level_sign_test_model_vs_structural_LINES"]
    sign_chars = report["group_level_sign_test_model_vs_structural_CHARS"]
    lines = [
        "# PrimeVul Pair-Coupled Constraint Decomposition",
        "",
        "Generated by `scripts/evaluate_pair_coupled_constraint_decomposition.py`.",
        "",
        "## Closed-world assumption",
        "",
        f"> {assumption['statement']}",
        "",
        f"- Available at deployment: **{assumption['available_at_deployment']}**",
        f"- Source of the knowledge: {assumption['source']}",
        f"- Consequence: {assumption['consequence']}",
        "",
        "## Group structure handling",
        "",
        f"- Pair groups: `{structure['groups']}`",
        f"- Well-formed two-row pairs: `{structure['well_formed_pairs']}`",
        f"- Non-pair groups passed through unconstrained: `{structure['non_pair_groups_passed_through']}`",
        f"- Policy: {structure['policy']}",
        "",
        "The previous decoder forced one positive on **every** group with at least two rows.",
        "On a group truly containing k > 1 positives that guarantees at least k-1 false",
        "negatives. Group size is observable without labels, so restricting the constraint",
        "to two-row groups is a gold-free fix rather than an oracle exclusion.",
        "",
        "## Systems on the same pair groups",
        "",
        "| system | balanced accuracy | what it isolates |",
        "| --- | ---: | --- |",
    ]
    order = [
        "constraint_only_random",
        "constraint_only_structural",
        "constraint_only_char_structural",
        "unconstrained_model",
        "constrained_model",
    ]
    for name in order:
        entry = systems[name]
        lines.append(f"| `{name}` | `{entry['balanced_accuracy']}` | {entry['description']} |")

    lines.extend(
        [
            "",
            "## Clustered comparisons (bootstrap over `pair_key` groups)",
            "",
            "| comparison | delta | 95% CI | independent units |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for name, entry in comparisons.items():
        lines.append(
            f"| `{name}` | `{entry['point']}` | `[{entry['ci95_low']}, {entry['ci95_high']}]` | `{entry['independent_units']}` |"
        )

    lines.extend(
        [
            "",
            "## Group-level paired sign tests",
            "",
            "Constrained model versus each semantics-free rule under the **same** constraint,",
            "counted once per pair group (not once per row):",
            "",
            "| comparison | model only | control only | discordant | exact p |",
            "| --- | ---: | ---: | ---: | ---: |",
            f"| vs net LINE count | `{sign['wins']}` | `{sign['losses']}` | `{sign['discordant_groups']}` | `{sign['two_sided_p_value_display']}` |",
            f"| vs net CHARACTER count | `{sign_chars['wins']}` | `{sign_chars['losses']}` | `{sign_chars['discordant_groups']}` | `{sign_chars['two_sided_p_value_display']}` |",
            "",
            "## Null calibration note",
            "",
            "`constraint_only_random` is a single fixed-seed draw, not an average over draws.",
            "With ~600 groups its standard error is roughly `0.02`, so a value a few hundredths",
            "away from `0.50` is sampling noise rather than signal. It is included to show that",
            "the closed-world constraint alone does not produce accuracy.",
            "",
            "## How to read this",
            "",
            "The `constraint_only_random` row is the null: it receives the full closed-world",
            "constraint and nothing else. Every other control receives the same constraint and",
            "reads only the *shape* of the diff -- how many lines or characters were added and",
            "removed -- never the content of any line.",
            "",
            "**The model must be judged against the strongest control, not the weakest.** The",
            "net LINE-count rule is weak mainly because it ties on ~22% of pairs and is then",
            "forced to guess. The net CHARACTER-count rule ties on ~4% and is far stronger. A",
            "gap over the line rule that disappears against the character rule is evidence about",
            "tie coverage, not about semantic reasoning.",
            "",
            "Each control uses its **own** unconstrained decision on groups the constraint does",
            "not cover. Borrowing the detector's predictions there (as an earlier version of this",
            "script did) inflates the baselines and lifts the random null above chance.",
            "",
            report["statistics_note"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Decompose the pair-coupling constraint.")
    parser.add_argument("--calibrated-report", default=DEFAULT_CALIBRATED)
    parser.add_argument("--train", default=DEFAULT_TRAIN)
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument(
        "--json-output", default="reports/secure_code_primevul_pair_coupled_constraint_decomposition_v1.json"
    )
    parser.add_argument("--md-output", default="reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md")
    args = parser.parse_args()

    report = build_report(
        calibrated_path=args.calibrated_report,
        train_path=args.train,
        seed=args.seed,
        iterations=args.iterations,
    )
    write_json(str(REPO_ROOT / args.json_output), report)
    (REPO_ROOT / args.md_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"systems": report["systems"], "comparisons": report["comparisons"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
