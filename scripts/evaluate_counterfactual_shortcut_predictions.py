from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.counterfactuals import evaluate_intervention_predictions
from vrf.io_utils import read_jsonl


def fmt(value):
    return "n/a" if value is None else f"{float(value):.4f}"


def render_markdown(report):
    lines = [
        "# Counterfactual Shortcut Evaluation",
        "",
        "This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.",
        "",
        "## Results",
        "",
        "| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |",
        "| --- | --- | ---: | --- | ---: | --- | --- |",
    ]
    for name, row in report["by_intervention"].items():
        ci = row["unexpected_change_ci95"]
        ci_text = "n/a" if ci is None else f"[{fmt(ci[0])}, {fmt(ci[1])}]"
        accuracy = (
            "n/a"
            if row["expected_label_rows"] == 0
            else f"{fmt(row['base_expected_label_accuracy'])} / {fmt(row['intervention_expected_label_accuracy'])}"
        )
        lines.append(
            f"| `{name}` | `{row['expected_relation']}` | `{fmt(row['unexpected_change_rate'])}` | `{ci_text}` | "
            f"`{fmt(row['mean_absolute_probability_shift'])}` | `{row['flip_0_to_1']} / {row['flip_1_to_0']}` | `{accuracy}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.",
            "- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.",
            "- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.",
            "- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate prediction stability under controlled shortcut interventions.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", default="reports/secure_code_counterfactual_shortcut_evaluation_v1.json")
    parser.add_argument("--markdown-output", default="reports/COUNTERFACTUAL_SHORTCUT_EVALUATION.md")
    args = parser.parse_args()
    report = evaluate_intervention_predictions(read_jsonl(ROOT / args.predictions))
    (ROOT / args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (ROOT / args.markdown_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
