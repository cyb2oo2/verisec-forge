"""Structural control vs. learned systems on the REPAIRED (v3) VeriPatch-RR suite.

The v1 comparison (``evaluate_veripatch_rr_structural_control.py``) ran on a
suite where 100% of DeltaSecommits rows were malformed by a source newline
defect, so nothing flipped under the side swap on that source. That suite is
retained untouched as the record of the contaminated state.

This script runs the same comparison on ``secure_code_relational_benchmark_v3``,
where every admitted pair satisfies the exact-mirror invariant
(``swap_mirror_is_exact``). Systems compared, all on identical pairs:

* ``control``           -- char_polarity, semantics-free, fit on train only
* ``baseline_independent`` / ``repaired_independent``   -- per-row decisions
* ``baseline_antisym``   / ``repaired_antisym``         -- the projection-null
  readout ``s = logit P(B | canonical) - logit P(B | side_swap)``

Metrics are pair-clustered and stratified by source.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any, Callable, Iterable

from vrf.polarity_control import diff_line_counts
from vrf.stats_cluster import group_sign_test, paired_cluster_bootstrap_diff

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
OUT = ROOT / "outputs"
REPORTS = ROOT / "reports"

TRAIN = DATA / "secure_code_primevul_joint_side_choice_train_v1.jsonl"

DEFAULT_AUDIT = DATA / "secure_code_qwen_mechanism_polarity_only_swap_audit_v3_runtime1024.jsonl"
DEFAULT_BASELINE_PREDS = OUT / "secure_code_v3_baseline_polarity_audit_predictions_1024.jsonl"
DEFAULT_REPAIRED_PREDS = OUT / "secure_code_v3_repaired_polarity_audit_predictions_1024.jsonl"
DEFAULT_OUTPUT = REPORTS / "veripatch_rr_structural_control_v3.json"

TIE_SEED = 20260804


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required artifact missing: {path}")
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def char_net(text: str) -> int:
    return diff_line_counts(text)["char_net"]


def _balanced_accuracy_ab(pairs: list[tuple[str, str]]) -> float:
    stats: dict[str, tuple[int, int]] = {}
    for gold, pred in pairs:
        hit, total = stats.get(gold, (0, 0))
        stats[gold] = (hit + int(pred == gold), total + 1)
    if not stats:
        return 0.0
    return sum(hit / total for hit, total in stats.values()) / len(stats)


def fit_rule(train_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Identical fitting protocol to the v1 script: training split only."""

    observations = [
        (char_net(row["text"]), str(row["vulnerable_side"]))
        for row in train_rows
        if row.get("text") and row.get("vulnerable_side") in ("A", "B")
    ]
    raw = sorted({score for score, _ in observations})
    midpoints = [(low + high) / 2 for low, high in zip(raw, raw[1:])]
    if len(midpoints) > 256:
        step = len(midpoints) / 256
        midpoints = [midpoints[int(index * step)] for index in range(256)]
    best: tuple[float, int, float] | None = None
    for sign in (1, -1):
        for threshold in [0.0] + midpoints:
            scored = []
            for score, gold in observations:
                value = sign * score
                if value > threshold:
                    scored.append((gold, "A"))
                elif value < threshold:
                    scored.append((gold, "B"))
            metric = _balanced_accuracy_ab(scored)
            if best is None or metric > best[0]:
                best = (metric, sign, threshold)
    assert best is not None
    metric, sign, threshold = best
    return {
        "sign": sign,
        "threshold": threshold,
        "train_balanced_accuracy": metric,
        "train_rows": len(observations),
    }


def _logit(probability: float) -> float:
    bounded = min(max(float(probability), 1e-9), 1 - 1e-9)
    return math.log(bounded / (1 - bounded))


def load_predictions(path: Path) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in read_jsonl(path)}


def build_systems(
    rows: list[dict[str, Any]],
    rule: dict[str, Any],
    *,
    baseline_preds: Path,
    repaired_preds: Path,
) -> dict[str, dict[str, str]]:
    """Per-row 'A'/'B' decisions for every system, keyed by row id."""

    rng = random.Random(TIE_SEED)
    control: dict[str, str] = {}
    for row in sorted(rows, key=lambda row: row["id"]):
        value = rule["sign"] * char_net(row["text"])
        if value > rule["threshold"]:
            control[row["id"]] = "A"
        elif value < rule["threshold"]:
            control[row["id"]] = "B"
        else:
            control[row["id"]] = rng.choice(("A", "B"))

    systems: dict[str, dict[str, str]] = {"control": control}
    canonical = {r["pair_key"]: r for r in rows if r["audit_variant"] == "canonical"}
    swap = {r["pair_key"]: r for r in rows if r["audit_variant"] == "side_swap"}

    for name, path in (("baseline", baseline_preds), ("repaired", repaired_preds)):
        predictions = load_predictions(path)
        systems[f"{name}_independent"] = {
            key: str(value["predicted_riskier_side"])
            for key, value in predictions.items()
            if value.get("predicted_riskier_side") in ("A", "B")
        }
        # Projection null: one decision per pair from the score difference.
        # Equivariance is exact by construction, so the swapped row receives the
        # mirrored decision.
        antisym: dict[str, str] = {}
        for pair_key, base in canonical.items():
            other = swap.get(pair_key)
            if other is None:
                continue
            first, second = predictions.get(base["id"]), predictions.get(other["id"])
            if not first or not second:
                continue
            if first.get("probability_b") is None or second.get("probability_b") is None:
                continue
            score = _logit(first["probability_b"]) - _logit(second["probability_b"])
            decision = "B" if score > 0 else "A"
            antisym[base["id"]] = decision
            antisym[other["id"]] = "A" if decision == "B" else "B"
        systems[f"{name}_antisym"] = antisym
    return systems


def _mean(values: Iterable[bool]) -> float:
    items = list(values)
    return sum(1 for value in items if value) / len(items) if items else 0.0


def canonical_accuracy(sample, preds) -> float:
    return _mean(
        preds.get(base["id"]) == str(base["gold_riskier_side"]) for base, _ in sample
    )


def both_correct(sample, preds) -> float:
    return _mean(
        preds.get(base["id"]) == str(base["gold_riskier_side"])
        and preds.get(other["id"]) == str(other["gold_riskier_side"])
        for base, other in sample
    )


def equivariance(sample, preds) -> float:
    return _mean(preds.get(base["id"]) != preds.get(other["id"]) for base, other in sample)


def independence_baseline(sample, preds) -> float:
    base_b = _mean(preds.get(base["id"]) == "B" for base, _ in sample)
    swap_b = _mean(preds.get(other["id"]) == "B" for _, other in sample)
    return base_b * (1 - swap_b) + (1 - base_b) * swap_b


METRICS: dict[str, Callable] = {
    "canonical_accuracy": canonical_accuracy,
    "side_swap_equivariance": equivariance,
    "both_directions_correct": both_correct,
    "independence_baseline": independence_baseline,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--baseline-predictions", type=Path, default=DEFAULT_BASELINE_PREDS)
    parser.add_argument("--repaired-predictions", type=Path, default=DEFAULT_REPAIRED_PREDS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--benchmark-label",
        default="secure_code_relational_benchmark_v3 (exact-mirror invariant enforced)",
    )
    args = parser.parse_args()

    rule = fit_rule(read_jsonl(TRAIN))
    rows = read_jsonl(args.audit)
    systems = build_systems(
        rows,
        rule,
        baseline_preds=args.baseline_predictions,
        repaired_preds=args.repaired_predictions,
    )

    canonical = {r["pair_key"]: r for r in rows if r["audit_variant"] == "canonical"}
    swap = {r["pair_key"]: r for r in rows if r["audit_variant"] == "side_swap"}
    groups = [(base, swap[key]) for key, base in canonical.items() if key in swap]

    by_source: dict[str, list] = {"ALL": groups}
    for base, other in groups:
        by_source.setdefault(str(base["dataset"]), []).append((base, other))

    payload: dict[str, Any] = {
        "rule": {"name": "char_polarity", "reads_line_content": False, **rule},
        "benchmark": args.benchmark_label,
        "audit": str(args.audit).replace("\\", "/"),
        "tie_break_seed": TIE_SEED,
        "pairs": len(groups),
        "results": {},
        "clustered_vs_control": {},
    }

    for source, sample in sorted(by_source.items()):
        payload["results"][source] = {
            "n_pairs": len(sample),
            **{
                system: {
                    metric: round(fn(sample, preds), 4)
                    for metric, fn in METRICS.items()
                }
                for system, preds in systems.items()
            },
        }
        entry: dict[str, Any] = {}
        for system, preds in systems.items():
            if system == "control":
                continue
            metrics_entry = {}
            for metric in ("canonical_accuracy", "both_directions_correct"):
                statistic = METRICS[metric]
                stats = paired_cluster_bootstrap_diff(
                    sample,
                    lambda group, fn=statistic: fn(group, systems["control"]),
                    lambda group, fn=statistic, p=preds: fn(group, p),
                )
                wins = sum(
                    1
                    for group in sample
                    if statistic([group], preds) > statistic([group], systems["control"])
                )
                losses = sum(
                    1
                    for group in sample
                    if statistic([group], preds) < statistic([group], systems["control"])
                )
                stats["group_sign_test"] = group_sign_test(wins, losses)
                metrics_entry[metric] = stats
            entry[system] = metrics_entry
        payload["clustered_vs_control"][source] = entry

    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.output}\n")

    order = [
        "control",
        "baseline_independent",
        "repaired_independent",
        "baseline_antisym",
        "repaired_antisym",
    ]
    for source in ["ALL"] + sorted(k for k in by_source if k != "ALL"):
        result = payload["results"][source]
        print(f"=== {source} (n={result['n_pairs']} pairs)")
        print(f"  {'system':22s} {'canonical':>10s} {'equivar':>9s} {'both':>8s} {'indep':>8s}")
        for system in order:
            values = result[system]
            print(
                f"  {system:22s} {values['canonical_accuracy']:>10.4f} "
                f"{values['side_swap_equivariance']:>9.4f} "
                f"{values['both_directions_correct']:>8.4f} "
                f"{values['independence_baseline']:>8.4f}"
            )
        for system, metrics_entry in payload["clustered_vs_control"][source].items():
            for metric, stats in metrics_entry.items():
                sign = stats["group_sign_test"]
                print(
                    f"    [{system} - control :: {metric:23s}] "
                    f"delta={stats['point']:+.4f} "
                    f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                    f"p={sign['two_sided_p_value_display']}"
                )
        print()


if __name__ == "__main__":
    main()
