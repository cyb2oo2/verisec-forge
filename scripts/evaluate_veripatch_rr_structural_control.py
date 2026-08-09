"""Run the semantics-free structural control as a competing SYSTEM on VeriPatch-RR.

Standing Rule 8 (docs/RESEARCH_INTEGRITY_REMEDIATION.md) requires every claim of
model signal to be measured against the strongest semantics-free control. That
rule was applied to the PrimeVul detector arc but never to the relational arc.
This script closes that gap.

The control reads only how many characters were added and removed in the
rendered diff -- never the content of any line. Sign and threshold are fit on
the side-choice TRAINING split only and applied unchanged to every audit
population.

Metric definitions are copied from ``src/vrf/cross_model_relational_analysis.py``
(``_swap_diagnostics``) so the numbers are directly comparable to the published
model numbers rather than a parallel invention.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Iterable

from vrf.polarity_control import diff_line_counts
from vrf.stats_cluster import group_sign_test, paired_cluster_bootstrap_diff

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
OUT = ROOT / "outputs"
REPORTS = ROOT / "reports"

TRAIN = DATA / "secure_code_primevul_joint_side_choice_train_v1.jsonl"

POLARITY_AUDIT = DATA / "secure_code_qwen_mechanism_polarity_only_swap_audit_v1_runtime1024.jsonl"
POLARITY_PREDS = OUT / "secure_code_qwen_mechanism_polarity_only_swap_audit_v1_predictions_1024.jsonl"

CROSSVUL_AUDIT = DATA / "secure_code_crossvul_polarity_only_swap_audit_v1_runtime1024.jsonl"
CROSSVUL_PREDS = OUT / "secure_code_crossvul_baseline_polarity_audit_predictions_1024.jsonl"

NUISANCE_AUDIT = DATA / "secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl"
NUISANCE_PREDS = OUT / "secure_code_nuisance_transfer_baseline_predictions_1024.jsonl"

# The paper's strongest system (Section 6): repaired model under antisymmetric
# inference. This is the fairest comparator for the control.
ANTISYM_PREDS = OUT / "secure_code_repair_antisymmetric_antisym_inference_predictions_1024.jsonl"
CROSSVUL_ANTISYM_PREDS = OUT / "secure_code_crossvul_repaired_antisym_inference_predictions_1024.jsonl"

TIE_SEED = 20260804


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required artifact missing: {path}")
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def char_net(text: str) -> int:
    """Semantics-free score: added characters minus removed characters.

    ``diff_line_counts`` inspects only line-leading ``+``/``-`` markers and
    excludes ``+++``/``---`` file headers, so no line content is ever read.
    """

    return diff_line_counts(text)["char_net"]


# ---------------------------------------------------------------------------
# Fitting: training split only
# ---------------------------------------------------------------------------


def _balanced_accuracy_ab(pairs: list[tuple[str, str]]) -> float:
    """Balanced accuracy over an A/B side label."""

    stats = {}
    for gold, pred in pairs:
        hit, total = stats.get(gold, (0, 0))
        stats[gold] = (hit + int(pred == gold), total + 1)
    if not stats:
        return 0.0
    return sum(hit / total for hit, total in stats.values()) / len(stats)


def fit_rule(train_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Fit sign and threshold for the char-polarity rule on training rows only."""

    observations = [
        (char_net(row["text"]), str(row["vulnerable_side"]))
        for row in train_rows
        if row.get("text") and row.get("vulnerable_side") in ("A", "B")
    ]
    if not observations:
        raise ValueError("cannot fit on zero training rows")

    raw = sorted({score for score, _ in observations})
    midpoints = [(low + high) / 2 for low, high in zip(raw, raw[1:])]
    max_candidates = 256
    if len(midpoints) > max_candidates:
        step = len(midpoints) / max_candidates
        midpoints = [midpoints[int(index * step)] for index in range(max_candidates)]
    grid = [0.0] + midpoints

    best: tuple[float, int, float] | None = None
    for sign in (1, -1):
        for threshold in grid:
            scored = []
            for score, gold in observations:
                value = sign * score
                if value > threshold:
                    scored.append((gold, "A"))
                elif value < threshold:
                    scored.append((gold, "B"))
            if not scored:
                continue
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


def predict(text: str, rule: dict[str, Any]) -> str | None:
    """Return 'A', 'B', or None when the rule ties."""

    value = rule["sign"] * char_net(text)
    if value > rule["threshold"]:
        return "A"
    if value < rule["threshold"]:
        return "B"
    return None


def resolve_ties(predictions: dict[str, str | None], seed: int) -> dict[str, str]:
    """Break ties with a seeded coin flip (matches the polarity-control report)."""

    rng = random.Random(seed)
    return {
        key: (value if value is not None else rng.choice(("A", "B")))
        for key, value in sorted(predictions.items())
    }


# ---------------------------------------------------------------------------
# Metrics (definitions copied from cross_model_relational_analysis._swap_diagnostics)
# ---------------------------------------------------------------------------


def _mean(values: Iterable[bool]) -> float:
    items = list(values)
    return sum(1 for value in items if value) / len(items) if items else 0.0


def swap_diagnostics(paired: list[dict[str, str]]) -> dict[str, float]:
    if not paired:
        return {}
    base_b = _mean(row["base_pred"] == "B" for row in paired)
    swap_b = _mean(row["swap_pred"] == "B" for row in paired)
    observed = _mean(row["base_pred"] != row["swap_pred"] for row in paired)
    baseline = base_b * (1.0 - swap_b) + (1.0 - base_b) * swap_b
    both = _mean(
        row["base_pred"] == row["base_gold"] and row["swap_pred"] == row["swap_gold"]
        for row in paired
    )
    return {
        "n_pairs": len(paired),
        "observed_equivariance": observed,
        "marginal_conditioned_independence_baseline": baseline,
        "observed_minus_baseline": observed - baseline,
        "both_directions_correct": both,
    }


def accuracy(rows: list[dict[str, Any]], preds: dict[str, str]) -> dict[str, float]:
    scored = [
        (str(row["gold_riskier_side"]), preds[row["id"]])
        for row in rows
        if row["id"] in preds
    ]
    hits = sum(1 for gold, pred in scored if gold == pred)
    return {"n": len(scored), "accuracy": hits / len(scored) if scored else 0.0}


# ---------------------------------------------------------------------------
# Evaluation of one audit population
# ---------------------------------------------------------------------------


def by_variant(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row["audit_variant"]), []).append(row)
    return groups


def rendering_antisymmetry(
    variants: dict[str, list[dict[str, Any]]]
) -> dict[str, float]:
    """How often is the swapped rendering an exact mirror of the canonical one?

    Where the mirror is broken, no diff-shape reader can flip, so the control is
    fed structurally invalid input. This is a property of the benchmark
    rendering, not of any system.
    """

    canonical = {row["pair_key"]: row for row in variants.get("canonical", [])}
    exact = mirrored_sign = total = 0
    for row in variants.get("side_swap", []):
        base = canonical.get(row["pair_key"])
        if base is None:
            continue
        base_net = char_net(base["text"])
        swap_net = char_net(row["text"])
        total += 1
        exact += int(base_net == -swap_net)
        mirrored_sign += int(
            (base_net > 0 and swap_net < 0) or (base_net < 0 and swap_net > 0)
        )
    if not total:
        return {}
    return {
        "n_pairs": total,
        "exact_char_net_antisymmetry": exact / total,
        "sign_flip_rate": mirrored_sign / total,
    }


def evaluate_population(
    rows: list[dict[str, Any]],
    systems: dict[str, dict[str, str]],
    rule: dict[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    raw = {row["id"]: predict(row["text"], rule) for row in rows}
    tie_rate = sum(1 for value in raw.values() if value is None) / len(raw) if raw else 0.0
    all_systems = {"control": resolve_ties(raw, TIE_SEED), **systems}

    variants = by_variant(rows)
    result: dict[str, Any] = {
        "label": label,
        "rows": len(rows),
        "variants": sorted(variants),
        "control_tie_rate": tie_rate,
        "rendering_antisymmetry": rendering_antisymmetry(variants),
        "accuracy": {},
        "swap": {},
        "clustered": {},
    }

    for name, variant_rows in sorted(variants.items()):
        decided = [row for row in variant_rows if raw.get(row["id"]) is not None]
        entry = {
            "control_decided_only": accuracy(decided, all_systems["control"])["accuracy"],
            "control_coverage": len(decided) / len(variant_rows) if variant_rows else 0.0,
        }
        for system, preds in all_systems.items():
            scored = accuracy(variant_rows, preds)
            entry[system] = scored["accuracy"]
            entry[f"{system}_n"] = scored["n"]
        result["accuracy"][name] = entry

    canonical = {row["pair_key"]: row for row in variants.get("canonical", [])}
    for name, variant_rows in sorted(variants.items()):
        if name == "canonical":
            continue
        for system, preds in all_systems.items():
            paired = []
            for row in variant_rows:
                base = canonical.get(row["pair_key"])
                if base is None or base["id"] not in preds or row["id"] not in preds:
                    continue
                paired.append(
                    {
                        "base_pred": preds[base["id"]],
                        "base_gold": str(base["gold_riskier_side"]),
                        "swap_pred": preds[row["id"]],
                        "swap_gold": str(row["gold_riskier_side"]),
                    }
                )
            result["swap"].setdefault(name, {})[system] = swap_diagnostics(paired)

    # Pair-clustered inference on the two headline quantities, control vs each
    # model system. Independent unit = pair_key group, per Standing Rule 5.
    swap_rows = {row["pair_key"]: row for row in variants.get("side_swap", [])}
    groups = [
        (base, swap_rows[key])
        for key, base in canonical.items()
        if key in swap_rows
    ]
    for system, preds in all_systems.items():
        if system == "control":
            continue
        shared = [
            group
            for group in groups
            if all(row["id"] in preds and row["id"] in all_systems["control"] for row in group)
        ]
        if not shared:
            continue

        def canonical_accuracy(sample, source):
            hits = [
                source[base["id"]] == str(base["gold_riskier_side"])
                for base, _ in sample
            ]
            return sum(hits) / len(hits) if hits else 0.0

        def both_correct(sample, source):
            hits = [
                source[base["id"]] == str(base["gold_riskier_side"])
                and source[swap["id"]] == str(swap["gold_riskier_side"])
                for base, swap in sample
            ]
            return sum(hits) / len(hits) if hits else 0.0

        # Stratify by whether the swapped rendering is an exact mirror. Where it
        # is not, no diff-shape reader can flip, so the control is structurally
        # crippled and any model advantage there is a rendering artifact.
        strata = {"exact_mirror": [], "broken_mirror": []}
        for base, swap in shared:
            key = (
                "exact_mirror"
                if char_net(base["text"]) == -char_net(swap["text"])
                else "broken_mirror"
            )
            strata[key].append((base, swap))
        stratified = {}
        for stratum, sample in strata.items():
            if not sample:
                continue
            stats = paired_cluster_bootstrap_diff(
                sample,
                lambda group: both_correct(group, all_systems["control"]),
                lambda group, p=preds: both_correct(group, p),
            )
            wins = sum(
                1
                for group in sample
                if both_correct([group], preds) > both_correct([group], all_systems["control"])
            )
            losses = sum(
                1
                for group in sample
                if both_correct([group], preds) < both_correct([group], all_systems["control"])
            )
            stats["group_sign_test"] = group_sign_test(wins, losses)
            stratified[stratum] = stats

        # Per-source view. The rendering defect is source-localised, so this is
        # the stratification that separates well-formed from malformed rows.
        by_source: dict[str, Any] = {}
        sources: dict[str, list] = {}
        for base, swap in shared:
            sources.setdefault(str(base["dataset"]), []).append((base, swap))
        for source, sample in sorted(sources.items()):
            source_entry = {}
            for metric_name, statistic in (
                ("canonical_accuracy", canonical_accuracy),
                ("both_directions_correct", both_correct),
            ):
                stats = paired_cluster_bootstrap_diff(
                    sample,
                    lambda group, fn=statistic: fn(group, all_systems["control"]),
                    lambda group, fn=statistic, p=preds: fn(group, p),
                )
                wins = sum(
                    1
                    for group in sample
                    if statistic([group], preds) > statistic([group], all_systems["control"])
                )
                losses = sum(
                    1
                    for group in sample
                    if statistic([group], preds) < statistic([group], all_systems["control"])
                )
                stats["group_sign_test"] = group_sign_test(wins, losses)
                source_entry[metric_name] = stats
            by_source[source] = source_entry

        entry = {
            "both_directions_correct_by_mirror_stratum": stratified,
            "by_source": by_source,
        }
        for metric_name, statistic in (
            ("canonical_accuracy", canonical_accuracy),
            ("both_directions_correct", both_correct),
        ):
            entry[metric_name] = paired_cluster_bootstrap_diff(
                shared,
                lambda sample, fn=statistic: fn(sample, all_systems["control"]),
                lambda sample, fn=statistic, p=preds: fn(sample, p),
            )
            wins = sum(
                1
                for group in shared
                if statistic([group], preds) > statistic([group], all_systems["control"])
            )
            losses = sum(
                1
                for group in shared
                if statistic([group], preds) < statistic([group], all_systems["control"])
            )
            entry[metric_name]["group_sign_test"] = group_sign_test(wins, losses)
        result["clustered"][f"{system}_minus_control"] = entry

    return result


def source_newline_defect() -> dict[str, Any]:
    """Verified root cause of the broken side-swap mirrors.

    ``difflib``'s matcher is exactly antisymmetric at the opcode level (checked
    with and without ``autojunk``). The mirrors break because some *source*
    records store an entire function on one line with no trailing newline. The
    unified diff then emits the added body on the same physical line as the
    removed body, leaving the row with no line-level polarity structure.
    """

    sources = {
        "primevul": DATA / "secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
        "deltasecommits": DATA / "secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl",
        "patcheval": DATA / "secure_code_patcheval_pair_diff_eval_metadata.jsonl",
    }
    summary = {}
    for name, path in sources.items():
        if not path.exists():
            continue
        rows = read_jsonl(path)[:400]
        single = sum(1 for row in rows if len(str(row.get("code") or "").splitlines()) <= 1)
        summary[name] = {
            "rows_checked": len(rows),
            "single_line_code_rate": single / len(rows) if rows else 0.0,
        }
    return summary


def split_view_prose_control(
    rows: list[dict[str, Any]], model_preds: dict[str, str]
) -> dict[str, Any]:
    """Is the polarity *information* still present under ``split_view``?

    ``split_view`` removes the ``+``/``-`` glyphs but states the same relation in
    English ("Removed from Side A", "Added in Side B"). This control reads the
    prose block headers and applies the identical net-character rule, so it
    measures whether the information survives the transformation independently of
    whether the model can use it.
    """

    removed_header = "Removed from Side A (absent in Side B):"
    added_header = "Added in Side B (absent in Side A):"
    context_header = "Unchanged context:"

    def prose_char_net(text: str) -> int | None:
        if removed_header not in text or added_header not in text:
            return None
        removed = text.split(removed_header, 1)[1].split(added_header, 1)[0]
        added = text.split(added_header, 1)[1].split(context_header, 1)[0]
        size = lambda block: sum(  # noqa: E731
            len(line.strip()) for line in block.split("\n") if line.strip()
        )
        return size(added) - size(removed)

    rng = random.Random(TIE_SEED)
    results = {}
    for variant in ("canonical__split_view", "side_swap__split_view"):
        subset = sorted(
            (row for row in rows if row["audit_variant"] == variant),
            key=lambda row: row["id"],
        )
        if not subset:
            continue
        control_hits = model_hits = ties = scored = 0
        for row in subset:
            value = prose_char_net(row["text"])
            if value is None:
                continue
            scored += 1
            ties += int(value == 0)
            prediction = "A" if value > 0 else ("B" if value < 0 else rng.choice(("A", "B")))
            control_hits += int(prediction == str(row["gold_riskier_side"]))
            model_hits += int(model_preds.get(row["id"]) == str(row["gold_riskier_side"]))
        results[variant] = {
            "n": scored,
            "prose_control_accuracy": control_hits / scored if scored else 0.0,
            "model_accuracy": model_hits / scored if scored else 0.0,
            "tie_rate": ties / scored if scored else 0.0,
        }
    return results


def load_model_preds(path: Path) -> dict[str, str]:
    return {
        row["id"]: str(row["predicted_riskier_side"])
        for row in read_jsonl(path)
        if row.get("predicted_riskier_side") in ("A", "B")
    }


def main() -> None:
    rule = fit_rule(read_jsonl(TRAIN))
    print(
        f"fitted char_polarity on {rule['train_rows']} training rows: "
        f"sign={rule['sign']} threshold={rule['threshold']:.3f} "
        f"train BA={rule['train_balanced_accuracy']:.4f}"
    )

    populations = []
    for label, audit_path, system_paths in (
        (
            "primevul_suite_polarity_audit",
            POLARITY_AUDIT,
            {"model": POLARITY_PREDS, "repaired_antisym": ANTISYM_PREDS},
        ),
        (
            "crossvul_polarity_audit",
            CROSSVUL_AUDIT,
            {"model": CROSSVUL_PREDS, "repaired_antisym": CROSSVUL_ANTISYM_PREDS},
        ),
        ("nuisance_transfer", NUISANCE_AUDIT, {"model": NUISANCE_PREDS}),
    ):
        rows = read_jsonl(audit_path)
        systems = {name: load_model_preds(path) for name, path in system_paths.items()}
        population = evaluate_population(rows, systems, rule, label=label)
        if label == "nuisance_transfer":
            population["split_view_prose_control"] = split_view_prose_control(
                rows, systems["model"]
            )
        populations.append(population)

    payload = {
        "rule": {
            "name": "char_polarity",
            "description": "net added-minus-removed CHARACTER count of the rendered diff",
            "reads_line_content": False,
            **rule,
        },
        "tie_break_seed": TIE_SEED,
        "metric_source": "src/vrf/cross_model_relational_analysis.py::_swap_diagnostics",
        "source_newline_defect": source_newline_defect(),
        "populations": populations,
    }

    destination = REPORTS / "veripatch_rr_structural_control_v1.json"
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {destination}")

    print("\n=== source newline defect (root cause of broken swap mirrors)")
    for name, stats in payload["source_newline_defect"].items():
        print(
            f"  {name:16s} single-line code rate="
            f"{stats['single_line_code_rate']:.4f} (n={stats['rows_checked']})"
        )

    for population in populations:
        print(f"\n=== {population['label']} (control tie rate {population['control_tie_rate']:.4f})")
        anti = population["rendering_antisymmetry"]
        if anti:
            print(
                f"  rendering: exact char_net antisymmetry="
                f"{anti['exact_char_net_antisymmetry']:.4f} "
                f"sign-flip={anti['sign_flip_rate']:.4f} (n={anti['n_pairs']})"
            )
        for name, entry in population["accuracy"].items():
            systems = " ".join(
                f"{key}={entry[key]:.4f}"
                for key in ("control", "model", "repaired_antisym")
                if key in entry
            )
            print(f"  {name:38s} {systems} (control coverage {entry['control_coverage']:.3f})")
        for name, systems in population["swap"].items():
            for system, stats in systems.items():
                if not stats:
                    continue
                print(
                    f"  [{name} | {system:16s}] equivariance="
                    f"{stats['observed_equivariance']:.4f} "
                    f"baseline={stats['marginal_conditioned_independence_baseline']:.4f} "
                    f"both_correct={stats['both_directions_correct']:.4f} "
                    f"n={stats['n_pairs']}"
                )
        for variant, stats in population.get("split_view_prose_control", {}).items():
            print(
                f"  [prose control] {variant:26s} "
                f"prose_control={stats['prose_control_accuracy']:.4f} "
                f"model={stats['model_accuracy']:.4f} n={stats['n']}"
            )
        for comparison, metrics in population["clustered"].items():
            for stratum, stats in metrics.get(
                "both_directions_correct_by_mirror_stratum", {}
            ).items():
                sign = stats["group_sign_test"]
                print(
                    f"  [{comparison} :: both_correct | {stratum:13s}] "
                    f"control={stats['baseline_point']:.4f} "
                    f"system={stats['system_point']:.4f} "
                    f"delta={stats['point']:+.4f} "
                    f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                    f"n={stats['independent_units']} "
                    f"p={sign['two_sided_p_value_display']}"
                )
            for source, source_metrics in metrics.get("by_source", {}).items():
                for metric_name, stats in source_metrics.items():
                    sign = stats["group_sign_test"]
                    print(
                        f"  [{comparison} :: {source:14s} {metric_name:23s}] "
                        f"control={stats['baseline_point']:.4f} "
                        f"system={stats['system_point']:.4f} "
                        f"delta={stats['point']:+.4f} "
                        f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                        f"p={sign['two_sided_p_value_display']}"
                    )
            for metric_name, stats in metrics.items():
                if metric_name in (
                    "both_directions_correct_by_mirror_stratum",
                    "by_source",
                ):
                    continue
                sign = stats["group_sign_test"]
                print(
                    f"  [{comparison} :: {metric_name}] "
                    f"delta={stats['point']:+.4f} "
                    f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                    f"sign {sign['wins']}-{sign['losses']} "
                    f"p={sign['two_sided_p_value_display']}"
                )


if __name__ == "__main__":
    main()
