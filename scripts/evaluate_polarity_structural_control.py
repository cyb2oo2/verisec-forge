"""Evaluate semantics-free structural controls against the paired-diff mainline.

The paired-diff formulation renders each row as a unified diff running from the
counterpart to the candidate. Because real security fixes are net-additive, the
*shape* of that diff correlates with the label without any security reasoning.
This script measures how far that shape alone gets, so the learned detector can
be reported against a meaningful floor instead of against chance.

Protocol
--------
* Every rule's sign and threshold is fit on the **training** split only.
* Rules are then applied unchanged to the **untouched evaluation** split.
* Ties (rules that abstain) are reported as coverage, and separately resolved by
  a fixed-seed coin flip so a full-eval number exists.
* The same rules are also run through the pair-coupling operator so the control
  is comparable to the pair-coupled system numbers.

Usage::

    python scripts/evaluate_polarity_structural_control.py \
        --json-output reports/secure_code_primevul_polarity_structural_control_v1.json \
        --md-output reports/PRIMEVUL_POLARITY_STRUCTURAL_CONTROL.md
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import statistics
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from vrf.artifact_guard import require_artifact  # noqa: E402
from vrf.io_utils import read_jsonl, write_json  # noqa: E402
from vrf.polarity_control import (  # noqa: E402
    CANDIDATE_SCORES,
    PolarityRule,
    fit_all_rules,
    row_features,
    row_gold,
)

DEFAULT_TRAIN = "data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl"
DEFAULT_EVAL = "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl"
DEFAULT_PREDICTIONS = (
    "outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_predictions.jsonl"
)
DEFAULT_MODEL_THRESHOLD = 0.6

REMEDIATION = {
    "produced_by": "scripts/build_primevul_pair_diff_dataset paths in REPRODUCIBILITY.md",
    "obtain": (
        "python scripts/download_reproducibility_bundle.py "
        "--bundle-name primevul_router_and_evidence_coupled_inputs --restore"
    ),
    "purpose": "semantics-free structural control for the paired-diff mainline",
}


def confusion(pairs: Sequence[tuple[int, int]]) -> dict[str, Any]:
    tp = sum(1 for gold, pred in pairs if gold == 1 and pred == 1)
    fn = sum(1 for gold, pred in pairs if gold == 1 and pred == 0)
    tn = sum(1 for gold, pred in pairs if gold == 0 and pred == 0)
    fp = sum(1 for gold, pred in pairs if gold == 0 and pred == 1)
    total = tp + fn + tn + fp
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "n": total,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def evaluate_rule(
    rule: PolarityRule,
    rows: Sequence[dict[str, Any]],
    *,
    tie_seed: int,
    draws: int,
    features: Sequence[dict[str, int]],
    golds: Sequence[int],
) -> dict[str, Any]:
    # Features are precomputed once by the caller: re-parsing the diff text
    # inside every bootstrap draw dominated runtime and changed no result.
    decisions = [rule.predict(feature) for feature in features]
    decided = [(gold, pred) for gold, pred in zip(golds, decisions) if pred is not None]
    ties = sum(1 for pred in decisions if pred is None)

    rng = random.Random(tie_seed)
    full_scores = []
    for _ in range(draws):
        pairs = [
            (gold, rng.randint(0, 1) if pred is None else pred)
            for gold, pred in zip(golds, decisions)
        ]
        full_scores.append(confusion(pairs)["balanced_accuracy"])

    return {
        "rule": rule.name,
        "description": rule.description,
        "fitted_on": "train split only",
        "fitted_sign": rule.sign,
        "fitted_threshold": rule.threshold,
        "coverage_excluding_ties": round(len(decided) / len(rows), 4) if rows else 0.0,
        "tie_rows": ties,
        "decided_rows": len(decided),
        "on_decided_rows": confusion(decided),
        "full_eval_balanced_accuracy_random_ties_mean": round(statistics.mean(full_scores), 4),
        "full_eval_balanced_accuracy_random_ties_sd": round(statistics.pstdev(full_scores), 4),
        "tie_resolution": f"fixed-seed coin flip, {draws} draws, seed={tie_seed}",
    }


def pair_coupled_rule_metrics(
    rule: PolarityRule,
    rows: Sequence[dict[str, Any]],
    *,
    seed: int,
    draws: int,
    features: Sequence[dict[str, int]],
) -> dict[str, Any]:
    """Rank rows inside each *well-formed pair* by the rule score.

    This mirrors ``apply_pair_coupling`` under its default
    ``well_formed_pairs_only`` policy: the one-positive constraint is applied
    only to two-row groups, and any other group keeps the rule's own
    unconstrained decision. Falling back to some other system's prediction here
    would contaminate the control and stop it being semantics-free.
    """

    groups: dict[str, list[tuple[int, float, int | None]]] = collections.defaultdict(list)
    for row, feature in zip(rows, features):
        groups[str(row.get("pair_key") or row["id"])].append(
            (row_gold(row), rule.score(feature), rule.predict(feature))
        )

    rng = random.Random(seed)
    scores = []
    for _ in range(draws):
        pairs: list[tuple[int, int]] = []
        for members in groups.values():
            if len(members) != 2:
                for gold, _score, decision in members:
                    pairs.append((gold, rng.randint(0, 1) if decision is None else decision))
                continue
            ranked = sorted(members, key=lambda item: (item[1], rng.random()), reverse=True)
            for index, (gold, _score, _decision) in enumerate(ranked):
                pairs.append((gold, 1 if index == 0 else 0))
        scores.append(confusion(pairs)["balanced_accuracy"])
    return {
        "pair_coupled_balanced_accuracy_mean": round(statistics.mean(scores), 4),
        "pair_coupled_balanced_accuracy_sd": round(statistics.pstdev(scores), 4),
        "groups": len(groups),
        "well_formed_pairs": sum(1 for members in groups.values() if len(members) == 2),
        "note": (
            "constraint applied only to two-row groups (matching apply_pair_coupling); other groups "
            "keep the rule's own unconstrained decision, never another system's prediction"
        ),
    }


def model_relationship(
    rule: PolarityRule,
    rows: Sequence[dict[str, Any]],
    predictions: Sequence[dict[str, Any]],
    *,
    threshold: float,
) -> dict[str, Any]:
    by_id = {str(row["id"]): row for row in rows}
    agree = 0
    compared = 0
    cond: collections.Counter = collections.Counter()
    model_pairs: list[tuple[int, int]] = []
    for prediction in predictions:
        row = by_id.get(str(prediction["id"]))
        if row is None:
            continue
        gold = row_gold(row)
        model = 1 if float(prediction["vuln_probability"]) >= threshold else 0
        model_pairs.append((gold, model))
        heuristic = rule.predict(row_features(row))
        if heuristic is None:
            continue
        compared += 1
        agree += int(model == heuristic)
        cond[(heuristic == gold, model == gold)] += 1

    heuristic_right = cond[(True, True)] + cond[(True, False)]
    heuristic_wrong = cond[(False, True)] + cond[(False, False)]
    return {
        "model_threshold": threshold,
        "model_rows": len(model_pairs),
        "model_metrics_full_eval": confusion(model_pairs),
        "rows_where_rule_decides": compared,
        "row_agreement_with_rule": round(agree / compared, 4) if compared else None,
        "model_accuracy_given_rule_correct": round(cond[(True, True)] / heuristic_right, 4) if heuristic_right else None,
        "model_accuracy_given_rule_incorrect": round(cond[(False, True)] / heuristic_wrong, 4)
        if heuristic_wrong
        else None,
        "n_rule_correct": heuristic_right,
        "n_rule_incorrect": heuristic_wrong,
    }


def build_report(
    *,
    train_path: str,
    eval_path: str,
    predictions_path: str | None,
    threshold: float,
    seed: int,
    draws: int,
) -> dict[str, Any]:
    require_artifact(train_path, **REMEDIATION)
    require_artifact(eval_path, **REMEDIATION)
    train_rows = read_jsonl(train_path)
    eval_rows = read_jsonl(eval_path)

    rules = fit_all_rules(train_rows)
    eval_features = [row_features(row) for row in eval_rows]
    eval_golds = [row_gold(row) for row in eval_rows]
    per_rule = {}
    for name, rule in rules.items():
        entry = evaluate_rule(
            rule, eval_rows, tie_seed=seed, draws=draws,
            features=eval_features, golds=eval_golds,
        )
        entry["pair_coupled"] = pair_coupled_rule_metrics(
            rule, eval_rows, seed=seed, draws=draws, features=eval_features
        )
        per_rule[name] = entry

    best_name = max(
        per_rule,
        key=lambda name: per_rule[name]["full_eval_balanced_accuracy_random_ties_mean"],
    )

    model_block: dict[str, Any] | None = None
    if predictions_path and (REPO_ROOT / predictions_path).exists():
        predictions = read_jsonl(predictions_path)
        model_block = model_relationship(rules[best_name], eval_rows, predictions, threshold=threshold)
    elif predictions_path:
        model_block = {
            "status": "unavailable",
            "missing_artifact": predictions_path,
            "obtain": REMEDIATION["obtain"],
        }

    return {
        "scope": "primevul_polarity_structural_control",
        "protocol": {
            "fit_split": train_path,
            "eval_split": eval_path,
            "fit_rule": "sign and threshold chosen by balanced accuracy on TRAIN rows only",
            "eval_untouched": True,
            "tie_policy": "reported as coverage; separately resolved by fixed-seed coin flip",
            "seed": seed,
            "draws": draws,
        },
        "train_rows": len(train_rows),
        "eval_rows": len(eval_rows),
        "rules": per_rule,
        "strongest_rule": best_name,
        "model_relationship": model_block,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rules = report["rules"]
    best = report["strongest_rule"]
    lines = [
        "# PrimeVul Polarity Structural Control",
        "",
        "Generated by `scripts/evaluate_polarity_structural_control.py`.",
        "",
        "This report supplies the missing negative control for the paired-diff",
        "formulation. Each rule below reads **only the shape of the diff** -- how many",
        "lines were added and removed -- and never the content of any line. Signs and",
        "thresholds are fit on the training split; the evaluation split is untouched.",
        "",
        "The three original negative controls (metadata-only, candidate-only,",
        "counterpart-only) all *remove* the diff, so none of them can test whether diff",
        "structure alone solves the task. These rules retain the structure and remove",
        "the semantics, which is the complementary control.",
        "",
        f"- Train rows: `{report['train_rows']}`",
        f"- Eval rows: `{report['eval_rows']}`",
        f"- Strongest semantics-free rule: `{best}`",
        "",
        "## Rules",
        "",
        "| rule | fitted sign | coverage (ties excluded) | BA on decided rows | accuracy | precision | recall | full-eval BA (random ties) | pair-coupled BA |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in sorted(rules, key=lambda key: -rules[key]["full_eval_balanced_accuracy_random_ties_mean"]):
        entry = rules[name]
        decided = entry["on_decided_rows"]
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{name}`",
                    str(entry["fitted_sign"]),
                    str(entry["coverage_excluding_ties"]),
                    str(decided["balanced_accuracy"]),
                    str(decided["accuracy"]),
                    str(decided["precision"]),
                    str(decided["recall"]),
                    str(entry["full_eval_balanced_accuracy_random_ties_mean"]),
                    str(entry["pair_coupled"]["pair_coupled_balanced_accuracy_mean"]),
                ]
            )
            + " |"
        )

    lines.extend(["", "### Rule definitions", ""])
    for name in sorted(rules):
        lines.append(f"- `{name}`: {CANDIDATE_SCORES[name][0]}")

    model = report.get("model_relationship")
    lines.extend(["", "## Relationship to the learned mainline detector", ""])
    if not model:
        lines.append("No model predictions were supplied.")
    elif model.get("status") == "unavailable":
        lines.extend(
            [
                f"Model predictions are unavailable (`{model['missing_artifact']}`).",
                "",
                f"Obtain with: `{model['obtain']}`",
            ]
        )
    else:
        metrics = model["model_metrics_full_eval"]
        lines.extend(
            [
                f"Comparison rule: `{best}`. Model decision threshold: `{model['model_threshold']}`.",
                "",
                "| quantity | value |",
                "| --- | ---: |",
                f"| learned detector balanced accuracy (full eval) | `{metrics['balanced_accuracy']}` |",
                f"| strongest semantics-free rule, full eval | `{rules[best]['full_eval_balanced_accuracy_random_ties_mean']}` |",
                f"| margin of learned detector over the rule | `{round(metrics['balanced_accuracy'] - rules[best]['full_eval_balanced_accuracy_random_ties_mean'], 4)}` |",
                f"| row agreement between detector and rule | `{model['row_agreement_with_rule']}` |",
                f"| detector accuracy where the rule is correct (n={model['n_rule_correct']}) | `{model['model_accuracy_given_rule_correct']}` |",
                f"| detector accuracy where the rule is **wrong** (n={model['n_rule_incorrect']}) | `{model['model_accuracy_given_rule_incorrect']}` |",
                "",
                "## Interpretation rule",
                "",
                "The detector may only be described as learning secure-patch semantics if it",
                "materially outperforms this control **and** succeeds where the control fails.",
                "The decisive quantity is the last row: detector accuracy conditional on the",
                "semantics-free rule being wrong. A value at or below chance means the detector",
                "follows the structural shortcut into its errors rather than correcting them.",
            ]
        )
        conditional = model["model_accuracy_given_rule_incorrect"]
        if conditional is not None:
            verdict = (
                "NOT MET: the detector does not succeed where the control fails."
                if conditional <= 0.5
                else "Partially met: the detector recovers on some rows where the control fails."
            )
            lines.extend(["", f"**Current verdict:** {verdict}"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate semantics-free structural controls.")
    parser.add_argument("--train", default=DEFAULT_TRAIN)
    parser.add_argument("--eval", dest="eval_path", default=DEFAULT_EVAL)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--model-threshold", type=float, default=DEFAULT_MODEL_THRESHOLD)
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument("--draws", type=int, default=200)
    parser.add_argument("--json-output", default="reports/secure_code_primevul_polarity_structural_control_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_POLARITY_STRUCTURAL_CONTROL.md")
    args = parser.parse_args()

    report = build_report(
        train_path=args.train,
        eval_path=args.eval_path,
        predictions_path=args.predictions,
        threshold=args.model_threshold,
        seed=args.seed,
        draws=args.draws,
    )
    write_json(str(REPO_ROOT / args.json_output), report)
    (REPO_ROOT / args.md_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"strongest_rule": report["strongest_rule"], "model": report["model_relationship"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
