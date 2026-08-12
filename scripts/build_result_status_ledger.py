"""Regenerate the Computed section of the result status ledger from JSON artifacts.

Every number in the ledger's Computed table is read from a machine-readable
result artifact. Hand-editing that section is what let three confidence
intervals drift out of agreement with the JSON they were supposedly summarising.

The generator rewrites only the block between the GENERATED markers; the
Historical, Withdrawn, and Awaiting-data sections are prose and are left alone.

Usage::

    python scripts/build_result_status_ledger.py            # rewrite in place
    python scripts/build_result_status_ledger.py --check     # exit 1 if stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from vrf.artifact_guard import require_artifact  # noqa: E402

LEDGER = "docs/RESULT_STATUS_LEDGER.md"
BEGIN = "<!-- BEGIN GENERATED: computed -->"
END = "<!-- END GENERATED: computed -->"

SOURCES = {
    "polarity": "reports/secure_code_primevul_polarity_structural_control_v1.json",
    "decomposition": "reports/secure_code_primevul_pair_coupled_constraint_decomposition_v1.json",
    "clustered": "reports/secure_code_primevul_pair_coupled_clustered_statistics_v1.json",
    "gate": "reports/secure_code_primevul_side_inversion_gate_uncertainty_v1.json",
    "training": "reports/current_shortcut_resistant_training_synthesis_v1.json",
}

REMEDIATION = {
    "produced_by": "scripts/run_clean_reproduction.py",
    "obtain": "python scripts/run_clean_reproduction.py",
    "purpose": "result status ledger Computed section",
}


def load() -> dict[str, Any]:
    payloads = {}
    for name, relative in SOURCES.items():
        require_artifact(relative, **REMEDIATION)
        payloads[name] = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    return payloads


def interval(entry: dict[str, Any]) -> str:
    return f"`{entry['point']:+.4f}`, 95% CI `[{entry['ci95_low']:+.4f}, {entry['ci95_high']:+.4f}]`"


def render(payloads: dict[str, Any]) -> str:
    polarity = payloads["polarity"]
    decomposition = payloads["decomposition"]
    clustered = payloads["clustered"]
    gate = payloads["gate"]
    training = payloads["training"]

    rules = polarity["rules"]
    best = polarity["strongest_rule"]
    strongest = rules[best]
    lines_rule = rules["net_polarity"]
    model = polarity["model_relationship"]
    systems = decomposition["systems"]
    comparisons = decomposition["comparisons"]
    chars_sign = decomposition["group_level_sign_test_model_vs_structural_CHARS"]
    lines_sign = decomposition["group_level_sign_test_model_vs_structural_LINES"]

    preferred_gate = next((row for row in gate["gates"] if row.get("is_preferred_gate")), None)

    polarity_doc = "[Polarity Structural Control](../reports/PRIMEVUL_POLARITY_STRUCTURAL_CONTROL.md)"
    decomposition_doc = "[Constraint Decomposition](../reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md)"
    clustered_doc = "[Clustered Statistics](../reports/PRIMEVUL_PAIR_COUPLED_CLUSTERED_STATISTICS.md)"
    gate_doc = "[Gate Uncertainty](../reports/PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md)"

    rows = [
        (
            f"Semantics-free structural control, strongest rule (`{best}`)",
            f"BA `{strongest['full_eval_balanced_accuracy_random_ties_mean']:.4f}` full eval / "
            f"`{strongest['on_decided_rows']['balanced_accuracy']:.4f}` on the "
            f"{strongest['coverage_excluding_ties'] * 100:.1f}% it decides",
            polarity_doc,
            "row",
        ),
        (
            "Weaker line-count rule (`net_polarity`), for context",
            f"BA `{lines_rule['full_eval_balanced_accuracy_random_ties_mean']:.4f}`; decides "
            f"{lines_rule['coverage_excluding_ties'] * 100:.1f}% of rows",
            "same",
            "row",
        ),
        (
            "Diff *size* alone is uninformative",
            f"`total_changed_lines` BA `{rules['total_changed_lines']['full_eval_balanced_accuracy_random_ties_mean']:.4f}` / "
            f"`total_changed_chars` BA `{rules['total_changed_chars']['full_eval_balanced_accuracy_random_ties_mean']:.4f}`",
            "same",
            "row",
        ),
        (
            "Learned detector, unconstrained",
            f"BA `{model['model_metrics_full_eval']['balanced_accuracy']:.4f}` — **below** the `{best}` control",
            "same",
            "row",
        ),
        (
            "Detector accuracy where the strongest control errs",
            f"`{model['model_accuracy_given_rule_incorrect']:.4f}` (n={model['n_rule_incorrect']}) — below chance",
            "same",
            "row",
        ),
        (
            "Constraint-only null (random orientation)",
            f"BA `{systems['constraint_only_random']['balanced_accuracy']:.4f}` (single draw, SE ≈ `0.02`)",
            decomposition_doc,
            "pair group",
        ),
        (
            "Constraint-only structural rule, net **lines**",
            f"BA `{systems['constraint_only_structural']['balanced_accuracy']:.4f}`",
            "same",
            "pair group",
        ),
        (
            "Constraint-only structural rule, net **characters** (strongest control)",
            f"BA `{systems['constraint_only_char_structural']['balanced_accuracy']:.4f}`",
            "same",
            "pair group",
        ),
        (
            "Unconstrained model",
            f"BA `{systems['unconstrained_model']['balanced_accuracy']:.4f}`",
            "same",
            "pair group",
        ),
        (
            "Constrained model",
            f"BA `{systems['constrained_model']['balanced_accuracy']:.4f}`",
            "same",
            "pair group",
        ),
        (
            "**Model vs strongest semantics-free control**",
            interval(comparisons["constrained_model_minus_constraint_only_structural_CHARS"])
            + " — **not distinguishable from zero**",
            "same",
            "pair group",
        ),
        (
            "Group-level sign test, model vs character rule",
            f"{chars_sign['wins']} vs {chars_sign['losses']}, `p = {chars_sign['two_sided_p_value_display']}`",
            "same",
            "pair group",
        ),
        (
            "Model vs weaker line-count rule (context only)",
            interval(comparisons["constrained_model_minus_constraint_only_structural_LINES"])
            + f"; sign test {lines_sign['wins']}–{lines_sign['losses']}",
            "same",
            "pair group",
        ),
        (
            "Pair coupling vs unconstrained same model (clustered)",
            interval(clustered["clustered_delta"]),
            clustered_doc,
            "pair group",
        ),
    ]

    if preferred_gate and preferred_gate.get("precision_pairs_exact_95_ci"):
        ci = preferred_gate["precision_pairs_exact_95_ci"]
        rows.append(
            (
                "Safe-flip gate precision, preferred gate",
                f"`{preferred_gate['precision_pairs_point']}` at **n={preferred_gate['accepted_pairs']} pairs**, "
                f"exact 95% CI `[{ci['low']}, {ci['high']}]`",
                gate_doc,
                "pair group",
            )
        )

    training_doc = "[Current Training Synthesis](../reports/CURRENT_SHORTCUT_RESISTANT_TRAINING_SYNTHESIS.md)"
    matched_arms = training["matched_compute"]["arms"]
    arm_means = {
        arm["backbone"]: arm["discordant_accuracy"]["mean"] for arm in matched_arms
    }
    rows.append(
        (
            "Matched-compute discordant accuracy, two-seed means",
            " / ".join(
                [
                    f"1.5B bf16 `{arm_means['Qwen2.5-Coder-1.5B bf16']:.4f}`",
                    f"7B nf4 `{arm_means['Qwen2.5-Coder-7B nf4']:.4f}`",
                    f"3B bf16 `{arm_means['Qwen2.5-Coder-3B bf16']:.4f}`",
                ]
            ),
            training_doc,
            "training seed",
        )
    )
    supply_arms = training["discordant_supply_control"]["arms"]
    rows.append(
        (
            "Discordant-supply control, two-seed mean accuracy",
            " / ".join(
                f"{arm['training_set'].split()[0]} `{arm['discordant_accuracy']['mean']:.4f}`"
                for arm in supply_arms
            ),
            "same",
            "training seed",
        )
    )
    precision = training["seed_precision"]
    rows.append(
        (
            "Seed precision sensitivity (95% mean half-width <= 0.05)",
            f"`{precision['required_seeds_for_95_half_width_at_most_0_05']}` seeds; "
            f"3-seed projected half-width `{precision['projected_95_half_width_at_3_seeds']:.4f}`",
            "same",
            "training seed",
        )
    )

    out = [
        BEGIN,
        "",
        "<!-- Generated by scripts/build_result_status_ledger.py from the JSON result",
        "     artifacts. Do not hand-edit: run the generator instead. -->",
        "",
        "| Result | Value | Where | Unit of inference |",
        "| --- | --- | --- | --- |",
    ]
    out.extend(f"| {name} | {value} | {where} | {unit} |" for name, value, where, unit in rows)
    out.extend(
        [
            "",
            "Sources: "
            + ", ".join(f"`{path}`" for path in SOURCES.values()),
            "",
            END,
        ]
    )
    return "\n".join(out)


def splice(text: str, block: str) -> str:
    start = text.index(BEGIN)
    end = text.index(END) + len(END)
    return text[:start] + block + text[end:]


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the ledger Computed section from JSON.")
    parser.add_argument("--check", action="store_true", help="exit 1 if the ledger is stale")
    args = parser.parse_args()

    path = REPO_ROOT / LEDGER
    text = path.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        print(f"{LEDGER} is missing the GENERATED markers", file=sys.stderr)
        return 1

    updated = splice(text, render(load()))
    if args.check:
        if updated != text:
            print(f"STALE: {LEDGER} does not match its JSON sources. Run scripts/build_result_status_ledger.py")
            return 1
        print(f"OK: {LEDGER} matches its JSON sources")
        return 0

    path.write_text(updated, encoding="utf-8")
    print(f"regenerated Computed section of {LEDGER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
