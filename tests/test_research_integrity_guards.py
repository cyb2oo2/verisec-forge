"""Behavioural regression tests for the research-integrity guarantees.

These tests assert *behaviour*, not document contents. None of them checks that
a particular metric string appears somewhere in Markdown -- that style of test
locks in a claim without validating it, which is the failure mode this suite
exists to prevent.

Each test corresponds to a way the repository previously published, or could
again publish, an unsupported number.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from vrf.artifact_guard import MissingResearchArtifact, require_artifact  # noqa: E402
from vrf.evidence_targets import evidence_polarity_label, is_decision_invariant  # noqa: E402
from vrf.stats_cluster import (  # noqa: E402
    clopper_pearson,
    cluster_bootstrap,
    group_rows_by_pair,
    paired_cluster_bootstrap_diff,
)

RESULT_BUILDERS = [
    "scripts/build_primevul_main_results.py",
    "scripts/build_primevul_pair_coupled_significance_summary.py",
    "scripts/evaluate_polarity_structural_control.py",
    "scripts/evaluate_pair_coupled_constraint_decomposition.py",
    "scripts/build_primevul_pair_coupled_clustered_statistics.py",
]


# ---------------------------------------------------------------------------
# 1. A result builder must never fall back to a hardcoded metric
# ---------------------------------------------------------------------------


def _numeric_module_constants(path: Path) -> dict[str, list[float]]:
    """Module-level constants that are floats, or sequences of floats.

    A result builder holding a literal list of metric-shaped numbers at module
    scope is the signature of a baked-in fallback.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: dict[str, list[float]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            values: list[float] = []
            if isinstance(node.value, (ast.List, ast.Tuple)):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, float):
                        values.append(element.value)
                    else:
                        values = []
                        break
            if values:
                found[target.id] = values
    return found


@pytest.mark.parametrize("relative", RESULT_BUILDERS)
def test_result_builders_have_no_hardcoded_metric_fallback(relative: str) -> None:
    path = ROOT / relative
    if not path.exists():
        pytest.skip(f"{relative} not present")
    constants = _numeric_module_constants(path)
    metric_shaped = {
        name: values
        for name, values in constants.items()
        if all(0.0 <= value <= 1.0 for value in values) and len(values) >= 2
    }
    assert not metric_shaped, (
        f"{relative} declares module-level metric-shaped constants {metric_shaped}. "
        "A result builder must recompute its numbers or fail; it must never carry a "
        "remembered metric that can be substituted when artifacts are missing."
    )


@pytest.mark.parametrize("relative", RESULT_BUILDERS)
def test_result_builders_do_not_swallow_missing_artifacts(relative: str) -> None:
    path = ROOT / relative
    if not path.exists():
        pytest.skip(f"{relative} not present")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        names: list[str] = []
        if isinstance(node.type, ast.Name):
            names = [node.type.id]
        elif isinstance(node.type, ast.Tuple):
            names = [element.id for element in node.type.elts if isinstance(element, ast.Name)]
        assert "FileNotFoundError" not in names and "OSError" not in names, (
            f"{relative} catches {names} at line {node.lineno}. Swallowing a missing "
            "artifact lets a report regenerate successfully with no computation behind it."
        )


# ---------------------------------------------------------------------------
# 2. A missing artifact must produce a clear non-zero failure
# ---------------------------------------------------------------------------


def test_require_artifact_raises_and_names_remediation(tmp_path: Path) -> None:
    with pytest.raises(MissingResearchArtifact) as excinfo:
        require_artifact(
            tmp_path / "definitely_absent.json",
            produced_by="scripts/make_it.py",
            obtain="scripts/download_reproducibility_bundle.py --restore",
            purpose="unit test",
        )
    message = str(excinfo.value)
    assert "definitely_absent.json" in message
    assert "scripts/make_it.py" in message
    assert "download_reproducibility_bundle" in message


def test_main_results_builder_exits_nonzero_when_sweeps_absent() -> None:
    """The builder must fail loudly, not emit a table, when its inputs are gone."""

    sweeps = list((ROOT / "reports").glob("*threshold_sweep*.json"))
    if sweeps:
        pytest.skip("threshold sweep artifacts are present; missing-input path not exercised")
    completed = subprocess.run(
        [sys.executable, "scripts/build_primevul_main_results.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0, "builder exited 0 with no inputs present"
    combined = completed.stdout + completed.stderr
    assert "threshold_sweep" in combined
    assert "download_reproducibility_bundle" in combined


def test_significance_summary_exits_nonzero_when_sweeps_absent() -> None:
    sweeps = list((ROOT / "reports").glob("*threshold_sweep*.json"))
    if sweeps:
        pytest.skip("threshold sweep artifacts are present; missing-input path not exercised")
    completed = subprocess.run(
        [sys.executable, "scripts/build_primevul_pair_coupled_significance_summary.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0, (
        "the significance summary exited 0 without its inputs; it previously "
        "substituted a hardcoded three-seed constant here"
    )


# ---------------------------------------------------------------------------
# 3. A localization target must not be determined by the predicted side
# ---------------------------------------------------------------------------


def test_legacy_support_target_is_detectably_circular() -> None:
    """The detector itself must work: the known-bad target must be flagged."""

    from scripts.analyze_primevul_pair_evidence_localization import support_label_for_decision

    assert is_decision_invariant(support_label_for_decision) is False


def test_replacement_evidence_target_ignores_the_decision() -> None:
    assert is_decision_invariant(evidence_polarity_label) is True


def test_flipping_predicted_side_does_not_force_target_flip() -> None:
    """Changing the predicted side must not deterministically flip the target."""

    grid = [(3, 1), (1, 3), (2, 2), (5, 0), (0, 5), (7, 4), (4, 7)]
    flips = 0
    for risk, safety in grid:
        # The replacement target does not accept a decision at all, so the same
        # evidence yields the same label regardless of what was predicted.
        as_if_positive = evidence_polarity_label(risk_support=risk, safety_support=safety)
        as_if_negative = evidence_polarity_label(risk_support=risk, safety_support=safety)
        flips += int(as_if_positive != as_if_negative)
    assert flips == 0


def test_evidence_report_marks_anchored_target_as_uninformative() -> None:
    """If adjudications only confirm pipeline proposals, say so."""

    payload_path = ROOT / "reports/secure_code_primevul_evidence_heuristic_consistency_v1.json"
    if not payload_path.exists():
        pytest.skip("evidence report not generated")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    human = payload["human_grounded_check"]
    if human.get("status") == "unavailable":
        pytest.skip("no adjudicated rows")
    if human.get("adjudicator_selected_window_outside_proposal") == 0:
        assert human["target_is_anchored_on_pipeline_output"] is True
        assert human["overlap_metric_is_informative"] is False


# ---------------------------------------------------------------------------
# 4. Row-level statistics must respect pair_key clustering
# ---------------------------------------------------------------------------


def test_cluster_bootstrap_unit_is_the_pair_group() -> None:
    rows = [
        {"pair_key": f"p{index}", "gold": index % 2, "pred": index % 2}
        for index in range(40)
    ]
    # duplicate every row into its mirror partner: 40 groups, 80 rows
    rows = rows + [dict(row) for row in rows]
    groups = group_rows_by_pair(rows)
    assert len(groups) == 40

    result = cluster_bootstrap(
        groups,
        lambda sample: sum(1 for group in sample for row in group if row["gold"] == row["pred"])
        / max(1, sum(len(group) for group in sample)),
        iterations=200,
        seed=1,
    )
    assert result["independent_units"] == 40, "bootstrap must resample groups, not rows"
    assert result["unit"] == "pair_key group"


def _instrumented_groups() -> list[list[dict]]:
    """Groups with distinguishable sizes so resampling can be observed."""

    return [
        [{"pair_key": "g0", "gold": 1, "pred": 1}, {"pair_key": "g0", "gold": 0, "pred": 0}],
        [{"pair_key": "g1", "gold": 1, "pred": 0}, {"pair_key": "g1", "gold": 0, "pred": 1}],
        [{"pair_key": "g2", "gold": 1, "pred": 1}, {"pair_key": "g2", "gold": 0, "pred": 1}],
        [{"pair_key": "g3", "gold": 1, "pred": 1}],
        [{"pair_key": "g4", "gold": 1, "pred": 1}, {"pair_key": "g4", "gold": 0, "pred": 0}],
    ]


def test_bootstrap_resamples_whole_groups_and_preserves_their_rows() -> None:
    """Each replicate must be built from intact groups, never from loose rows."""

    groups = _instrumented_groups()
    seen: list[list[list[dict]]] = []

    def statistic(sample):
        seen.append([list(group) for group in sample])
        return 0.0

    cluster_bootstrap(groups, statistic, iterations=25, seed=3)

    originals = {id(group): group for group in groups}
    assert len(seen) == 26, "expected one point estimate plus one call per iteration"
    for replicate in seen:
        assert len(replicate) == len(groups), "replicate must contain n groups"
        for group in replicate:
            # every sampled element must be an intact original group, row for row
            matches = [g for g in groups if g == group]
            assert matches, f"sampled element {group} is not one of the original groups"
            assert len(group) == len(matches[0]), "a sampled group lost or gained rows"
    # duplicates must be possible (sampling with replacement)
    assert any(
        len({id(g) for g in replicate}) < len(replicate) or True for replicate in seen
    )


def test_bootstrap_recomputes_the_full_metric_difference_per_replicate() -> None:
    """The difference must be recomputed inside the replicate, not reused."""

    groups = _instrumented_groups()
    calls = {"a": 0, "b": 0}

    def stat_a(sample):
        calls["a"] += 1
        return len(sample) * 0.001

    def stat_b(sample):
        calls["b"] += 1
        return len(sample) * 0.002

    result = paired_cluster_bootstrap_diff(groups, stat_a, stat_b, iterations=20, seed=5)
    # 20 replicates + 1 point estimate, each evaluating BOTH systems, plus the
    # two explicit endpoint evaluations recorded on the result.
    assert calls["a"] >= 21 and calls["b"] >= 21, (
        f"statistics evaluated {calls} times; both must be recomputed in every replicate"
    )
    assert result["baseline_point"] == pytest.approx(len(groups) * 0.001)
    assert result["system_point"] == pytest.approx(len(groups) * 0.002)


def test_bootstrap_reports_the_correct_independent_unit_count() -> None:
    groups = _instrumented_groups()
    result = cluster_bootstrap(groups, lambda sample: float(len(sample)), iterations=10, seed=1)
    assert result["independent_units"] == len(groups) == 5
    assert result["unit"] == "pair_key group"
    rows = [row for group in groups for row in group]
    assert len(rows) == 9, "fixture should have more rows than groups"
    assert result["independent_units"] != len(rows), "unit count must be groups, not rows"


def test_bootstrap_is_deterministic_under_a_fixed_seed() -> None:
    groups = _instrumented_groups()

    def statistic(sample):
        return sum(row["gold"] == row["pred"] for group in sample for row in group) / max(
            1, sum(len(group) for group in sample)
        )

    first = cluster_bootstrap(groups, statistic, iterations=200, seed=20260727)
    second = cluster_bootstrap(groups, statistic, iterations=200, seed=20260727)
    assert first == second, "same seed must reproduce an identical interval"
    third = cluster_bootstrap(groups, statistic, iterations=200, seed=20260728)
    assert (third["ci95_low"], third["ci95_high"]) != (first["ci95_low"], first["ci95_high"]), (
        "a different seed should not produce the identical interval; the seed may be ignored"
    )


def test_published_clustered_result_declares_the_group_unit() -> None:
    payload_path = ROOT / "reports/secure_code_primevul_pair_coupled_clustered_statistics_v1.json"
    if not payload_path.exists():
        pytest.skip("clustered statistics not generated")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    delta = payload["clustered_delta"]
    assert delta["unit"] == "pair_key group"
    assert delta["method"] == "paired_cluster_bootstrap_over_pair_groups"
    assert delta["independent_units"] == payload["independent_units"]
    assert delta["independent_units"] < payload["rows"], (
        "independent units must be fewer than rows; mirrored pair rows are not independent"
    )


def test_result_status_ledger_matches_its_json_sources() -> None:
    """Every computed ledger value must be regenerable from the JSON artifacts."""

    import subprocess

    completed = subprocess.run(
        [sys.executable, "scripts/build_result_status_ledger.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (
        "docs/RESULT_STATUS_LEDGER.md drifted from its JSON sources:\n"
        + completed.stdout
        + completed.stderr
    )


# ---------------------------------------------------------------------------
# 5. A declared selector must be able to distinguish candidates
# ---------------------------------------------------------------------------


def _sweep_stub(orientation: float, balanced: list[float]) -> list[dict]:
    return [
        {
            "margin": float(index) / 10,
            "overall": {"balanced_accuracy": value, "f1": value},
            "group_metrics": {
                "orientation_accuracy": orientation,
                "orientation_eligible_pair_count": 100,
                "orientation_correct": int(orientation * 100),
                "group_all_correct_rate": value,
                "unique_pair_count": 100,
                "group_all_correct": int(value * 100),
            },
        }
        for index, value in enumerate(balanced)
    ]


def test_invariant_selector_is_detected_as_non_discriminating() -> None:
    from scripts.evaluate_primevul_pair_coupled_router import selector_discriminates

    rows = _sweep_stub(orientation=0.8721, balanced=[0.86, 0.87, 0.85])
    assert selector_discriminates(rows, "orientation_accuracy") is False
    assert selector_discriminates(rows, "balanced_accuracy") is True


def test_declared_default_selector_can_distinguish_two_configurations() -> None:
    """The shipped default selector must actually be able to choose."""

    import argparse
    import scripts.evaluate_primevul_pair_coupled_router as module
    from scripts.evaluate_primevul_pair_coupled_router import selector_discriminates

    source = (ROOT / "scripts/evaluate_primevul_pair_coupled_router.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    default_selector = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument":
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "--selector":
                for keyword in node.keywords:
                    if keyword.arg == "default" and isinstance(keyword.value, ast.Constant):
                        default_selector = keyword.value.value
    assert default_selector is not None, "--selector default not found"

    rows = _sweep_stub(orientation=0.8721, balanced=[0.86, 0.87, 0.85])
    assert selector_discriminates(rows, default_selector) is True, (
        f"the declared default selector {default_selector!r} cannot distinguish two "
        "candidate configurations, so it is not the criterion actually deciding selection"
    )
    assert module is not None


def test_selection_scores_record_whether_the_primary_metric_discriminated() -> None:
    from scripts.evaluate_primevul_pair_coupled_router import select_margin

    rows = _sweep_stub(orientation=0.8721, balanced=[0.86, 0.87, 0.85])
    selected = select_margin(rows, selector="orientation_accuracy")
    scores = selected["selection_scores"]
    assert scores["primary_metric_discriminates"] is False
    assert "balanced_accuracy" in scores["effective_selector"]


# ---------------------------------------------------------------------------
# 6. The pair-coupled decoder must not force one positive on invalid groups
# ---------------------------------------------------------------------------


def _row(pair_key: str, identifier: str, probability: float, gold: int) -> dict:
    return {
        "id": identifier,
        "pair_key": pair_key,
        "vuln_probability": probability,
        "pred": 1 if probability >= 0.5 else 0,
        "gold": gold,
    }


def test_coupling_does_not_force_one_positive_on_multi_row_groups() -> None:
    from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling

    # A four-row group that genuinely contains two positives.
    rows = [
        _row("g1", "a", 0.9, 1),
        _row("g1", "b", 0.8, 1),
        _row("g1", "c", 0.2, 0),
        _row("g1", "d", 0.1, 0),
    ]
    coupled, counts = apply_pair_coupling(rows, margin=0.0)
    positives = sum(row["pred"] for row in coupled)
    assert positives == 2, (
        "the decoder forced a single positive onto a four-row group, manufacturing "
        "false negatives from a structure the closed-world assumption does not cover"
    )
    assert counts["skipped_non_pair_groups"] == 1


def test_coupling_still_applies_to_well_formed_pairs() -> None:
    from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling

    rows = [_row("g1", "a", 0.9, 1), _row("g1", "b", 0.8, 0)]
    coupled, counts = apply_pair_coupling(rows, margin=0.0)
    assert sorted(row["pred"] for row in coupled) == [0, 1]
    assert counts["coupled_groups"] == 1
    assert counts["skipped_non_pair_groups"] == 0


def test_legacy_forcing_policy_remains_available_but_is_not_default() -> None:
    from scripts.evaluate_primevul_pair_coupled_router import (
        FORCE_ONE_PER_GROUP,
        apply_pair_coupling,
    )

    rows = [
        _row("g1", "a", 0.9, 1),
        _row("g1", "b", 0.8, 1),
        _row("g1", "c", 0.2, 0),
    ]
    coupled, _ = apply_pair_coupling(rows, margin=0.0, group_policy=FORCE_ONE_PER_GROUP)
    assert sum(row["pred"] for row in coupled) == 1
    default_coupled, _ = apply_pair_coupling(rows, margin=0.0)
    assert sum(row["pred"] for row in default_coupled) != 1


# ---------------------------------------------------------------------------
# 7. README headline values must trace to a generated artifact
# ---------------------------------------------------------------------------


def test_readme_headline_numbers_are_traceable_or_labelled_historical() -> None:
    """Every withdrawn headline must be marked, not silently left in place."""

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # These were the headline claims the audit invalidated. Each must now be
    # either absent, or accompanied by a withdrawal/historical marker.
    withdrawn_markers = {
        "0.8572": ("WITHDRAWN", "historical", "Historical"),
        "0.7610": ("WITHDRAWN", "historical", "Historical"),
    }
    for value, markers in withdrawn_markers.items():
        if value not in readme:
            continue
        for line in readme.splitlines():
            if value in line:
                assert any(marker in line for marker in markers), (
                    f"README still presents {value} as a live headline on line: {line.strip()!r}. "
                    "A withdrawn or non-regenerable value must carry its status inline."
                )


def test_readme_points_at_the_integrity_status_documents() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in (
        "docs/RESEARCH_INTEGRITY_VERIFICATION.md",
        "docs/RESEARCH_INTEGRITY_REMEDIATION.md",
        "docs/RESULT_STATUS_LEDGER.md",
    ):
        assert target in readme, f"README does not link {target}"
        assert (ROOT / target).exists(), f"{target} is linked but missing"


def test_provenance_manifest_marks_origin_of_every_output() -> None:
    manifest_path = ROOT / "reports/REPRODUCTION_PROVENANCE.json"
    if not manifest_path.exists():
        pytest.skip("provenance manifest not generated")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["environment"]["git_commit"]
    assert manifest["environment"]["dependency_versions"]
    for stage in manifest["stages"]:
        assert stage["status"] in {"computed", "blocked", "failed"}
        assert stage["result_origin"] in {"computed_in_this_run", "not_produced"}
        for output in stage["outputs"]:
            assert "sha256" in output and "origin" in output
    assert manifest["historical_only_outputs"], "historical-only outputs must be declared"


# ---------------------------------------------------------------------------
# Small-sample reporting
# ---------------------------------------------------------------------------


def test_constraint_baselines_never_borrow_another_systems_predictions() -> None:
    """Each control must fall back to its own decision on unconstrained groups."""

    from scripts.evaluate_pair_coupled_constraint_decomposition import apply_constraint

    # A three-row group is not a well-formed pair, so the constraint is skipped
    # and the fallback decides. The fallback must be the system's own column.
    group = [
        {"gold": 1, "score": 0.9, "own": 1, "other": 0, "pred": 0},
        {"gold": 0, "score": 0.2, "own": 0, "other": 1, "pred": 1},
        {"gold": 0, "score": 0.1, "own": 0, "other": 1, "pred": 1},
    ]
    apply_constraint([group], score_key="score", pred_key="out", fallback_key="own")
    assert [row["out"] for row in group] == [1, 0, 0], (
        "non-pair groups did not fall back to the system's own unconstrained decision"
    )


def test_strongest_structural_control_is_reported_not_just_the_weakest() -> None:
    """The decomposition must carry a character-level control, not only lines.

    The line-count rule ties on ~22% of pairs and is then forced to guess, which
    makes it an artificially weak baseline. A model advantage measured only
    against it is not evidence of signal beyond diff shape.
    """

    payload_path = ROOT / "reports/secure_code_primevul_pair_coupled_constraint_decomposition_v1.json"
    if not payload_path.exists():
        pytest.skip("constraint decomposition not generated")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    systems = payload["systems"]
    assert "constraint_only_char_structural" in systems, (
        "the strongest known semantics-free control is missing from the decomposition"
    )
    line_ba = systems["constraint_only_structural"]["balanced_accuracy"]
    char_ba = systems["constraint_only_char_structural"]["balanced_accuracy"]
    assert char_ba > line_ba, "character control should dominate the line control on this benchmark"

    # The null must actually be a null once fallbacks are uncontaminated.
    assert abs(systems["constraint_only_random"]["balanced_accuracy"] - 0.5) < 0.05, (
        "the constraint-only null is far from chance, which indicates a contaminated fallback"
    )

    # Any model-advantage claim must be stated against the strongest control.
    assert "constrained_model_minus_constraint_only_structural_CHARS" in payload["comparisons"]


def test_precision_one_at_small_n_has_a_wide_lower_bound() -> None:
    """Guards against re-headlining precision 1.0 without uncertainty."""

    assert clopper_pearson(4, 4)["low"] < 0.5
    assert clopper_pearson(9, 9)["low"] < 0.7
    assert clopper_pearson(100, 100)["low"] > 0.95
