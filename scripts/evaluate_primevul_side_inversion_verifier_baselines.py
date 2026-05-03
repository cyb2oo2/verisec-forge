from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_jsonl, write_json

SIGNAL_RE = re.compile(r"Signals:\s*risk=([-+]?\d+(?:\.\d+)?)\s+safety=([-+]?\d+(?:\.\d+)?)")


def safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def side_text(prompt: str, side: str) -> str:
    marker = f"Side {side} windows:"
    other_marker = "Side B windows:" if side == "A" else ""
    if marker not in prompt:
        return ""
    text = prompt.split(marker, 1)[1]
    if other_marker and other_marker in text:
        text = text.split(other_marker, 1)[0]
    return text


def risk_safety_totals(text: str) -> tuple[float, float]:
    risk = 0.0
    safety = 0.0
    for match in SIGNAL_RE.finditer(text):
        risk += safe_float(match.group(1))
        safety += safe_float(match.group(2))
    return risk, safety


def evidence_score(row: dict[str, Any]) -> float:
    prompt = str(row.get("prompt", ""))
    side_a_risk, side_a_safety = risk_safety_totals(side_text(prompt, "A"))
    side_b_risk, side_b_safety = risk_safety_totals(side_text(prompt, "B"))
    # Flip support rises when A looks safer and B looks riskier.
    return (side_b_risk + side_a_safety) - (side_a_risk + side_b_safety)


def gold(row: dict[str, Any]) -> int:
    return int(bool(row.get("accept_flip")))


def metric(rows: list[dict[str, Any]], predictions: list[int], *, name: str) -> dict[str, Any]:
    tp = tn = fp = fn = 0
    for row, pred in zip(rows, predictions, strict=True):
        label = gold(row)
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 0 and label == 0:
            tn += 1
        elif pred == 1 and label == 0:
            fp += 1
        else:
            fn += 1
    total = tp + tn + fp + fn
    accept_recall = tp / (tp + fn) if tp + fn else 0.0
    reject_specificity = tn / (tn + fp) if tn + fp else 0.0
    accept_precision = tp / (tp + fp) if tp + fp else 0.0
    reject_precision = tn / (tn + fn) if tn + fn else 0.0
    return {
        "name": name,
        "rows": total,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "balanced_accuracy": round((accept_recall + reject_specificity) / 2, 4),
        "accept_recall": round(accept_recall, 4),
        "reject_specificity": round(reject_specificity, 4),
        "accept_precision": round(accept_precision, 4),
        "reject_precision": round(reject_precision, 4),
        "accepted": tp + fp,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def score_threshold_metrics(rows: list[dict[str, Any]], thresholds: list[float]) -> list[dict[str, Any]]:
    metrics = []
    for threshold in thresholds:
        predictions = [int(safe_float(row.get("side_model_score")) >= threshold) for row in rows]
        metrics.append(metric(rows, predictions, name=f"side_model_score>={threshold:g}"))
    return metrics


def evidence_threshold_metrics(rows: list[dict[str, Any]], thresholds: list[float]) -> list[dict[str, Any]]:
    scores = [evidence_score(row) for row in rows]
    metrics = []
    for threshold in thresholds:
        predictions = [int(score >= threshold) for score in scores]
        metrics.append(metric(rows, predictions, name=f"evidence_margin>={threshold:g}"))
    return metrics


def best_by(metrics: list[dict[str, Any]], key: str) -> dict[str, Any]:
    return max(metrics, key=lambda row: (float(row[key]), float(row["accept_precision"]), float(row["accuracy"])))


def build_report(rows: list[dict[str, Any]], *, score_thresholds: list[float], evidence_thresholds: list[float]) -> dict[str, Any]:
    metrics = [
        metric(rows, [1 for _ in rows], name="accept_all"),
        metric(rows, [0 for _ in rows], name="reject_all"),
    ]
    metrics.extend(score_threshold_metrics(rows, score_thresholds))
    metrics.extend(evidence_threshold_metrics(rows, evidence_thresholds))
    scores = [evidence_score(row) for row in rows]
    positives = [score for score, row in zip(scores, rows, strict=True) if gold(row) == 1]
    negatives = [score for score, row in zip(scores, rows, strict=True) if gold(row) == 0]
    return {
        "config": {
            "score_thresholds": score_thresholds,
            "evidence_thresholds": evidence_thresholds,
        },
        "summary": {
            "rows": len(rows),
            "accept_flip_rows": sum(gold(row) for row in rows),
            "reject_flip_rows": sum(1 for row in rows if gold(row) == 0),
            "best_balanced_accuracy": best_by(metrics, "balanced_accuracy"),
            "best_accept_precision": best_by(metrics, "accept_precision"),
            "evidence_score_mean_accept": round(sum(positives) / len(positives), 4) if positives else 0.0,
            "evidence_score_mean_reject": round(sum(negatives) / len(negatives), 4) if negatives else 0.0,
        },
        "metrics": metrics,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Side-Inversion Verifier Baselines",
        "",
        "This report evaluates lightweight baselines for the strict `accept_flip` verifier target. It is a signal check before training a GPU-backed verifier.",
        "",
        "## Summary",
        "",
        f"- Rows: `{summary['rows']}`",
        f"- Accept / reject rows: `{summary['accept_flip_rows']}` / `{summary['reject_flip_rows']}`",
        f"- Best balanced-accuracy baseline: `{summary['best_balanced_accuracy']['name']}` at `{summary['best_balanced_accuracy']['balanced_accuracy']}`",
        f"- Best accept-precision baseline: `{summary['best_accept_precision']['name']}` at `{summary['best_accept_precision']['accept_precision']}`",
        f"- Evidence score mean accept / reject: `{summary['evidence_score_mean_accept']}` / `{summary['evidence_score_mean_reject']}`",
        "",
        "## Metrics",
        "",
        "| baseline | accuracy | bal_acc | accept_recall | reject_specificity | accept_precision | accepted | tp | tn | fp | fn |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["metrics"]:
        lines.append(
            f"| {row['name']} | {row['accuracy']} | {row['balanced_accuracy']} | {row['accept_recall']} | "
            f"{row['reject_specificity']} | {row['accept_precision']} | {row['accepted']} | {row['tp']} | "
            f"{row['tn']} | {row['fp']} | {row['fn']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A useful trained verifier should beat these rules on held-out pair groups while preserving high accept precision. If a simple evidence-margin rule already dominates, the next step should improve evidence extraction rather than train a broader language-model verifier.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_floats(value: str) -> list[float]:
    parsed = [float(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one threshold is required")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate lightweight baselines for side-inversion verifier targets.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--score-thresholds", default="0.5,0.9,0.99,0.999")
    parser.add_argument("--evidence-thresholds", default="-5,0,5,10")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    payload = build_report(
        read_jsonl(args.input),
        score_thresholds=parse_floats(args.score_thresholds),
        evidence_thresholds=parse_floats(args.evidence_thresholds),
    )
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
