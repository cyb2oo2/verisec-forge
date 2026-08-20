from __future__ import annotations

import math

import pytest

from vrf.pair_decision import (
    antisymmetric_label,
    build_pairs,
    control_label,
    independent_label,
    logit,
    pair_scores,
    summarise_outcomes,
)
from vrf.relational_report_contract import (
    RelationalReportContractError,
    exact_mirror_rejection_table,
    require_relational_report_contract,
    suite_version_from_summary,
)


def test_logit_is_symmetric_and_stable() -> None:
    assert logit(0.5) == pytest.approx(0.0)
    assert logit(0.9) == pytest.approx(-logit(0.1))
    assert math.isfinite(logit(0.0))
    assert math.isfinite(logit(1.0))


def test_independent_label_uses_shared_threshold() -> None:
    assert independent_label(0.49) == "A"
    assert independent_label(0.5) == "B"
    assert independent_label(0.6, threshold=0.7) == "A"
    assert independent_label(0.7, threshold=0.7) == "B"


def test_antisymmetric_label_is_the_score_difference() -> None:
    assert antisymmetric_label(0.8, 0.2) == "B"
    assert antisymmetric_label(0.2, 0.8) == "A"
    assert antisymmetric_label(0.5, 0.5) == "A"


def test_control_label_is_char_net_sign() -> None:
    assert control_label(12) == "A"
    assert control_label(-3) == "B"
    assert control_label(0) is None


def _suite_row(
    *,
    pair_key: str,
    family: str,
    variant: str,
    gold: str,
    text: str,
    balanced: bool = True,
    dataset: str = "primevul",
) -> dict:
    return {
        "id": f"v4::{dataset}::{pair_key}::{family}::{variant}",
        "pair_key": pair_key,
        "dataset": dataset,
        "gold_riskier_side": gold,
        "rendering_family": family,
        "audit_variant": variant if family == "glyph" else f"prose__{variant}",
        "polarity_balanced_slice": balanced,
        "text": text,
    }


def test_build_pairs_reads_net_from_glyph_and_drops_zero_net() -> None:
    glyph_plus = "Unified diff:\n-old\n+new line here\n"
    glyph_zero = "Unified diff:\n-ab\n+cd\n"
    rows = [
        _suite_row(pair_key="p1", family="glyph", variant="canonical", gold="A", text=glyph_plus),
        _suite_row(pair_key="p1", family="glyph", variant="side_swap", gold="B", text=glyph_plus),
        _suite_row(pair_key="p1", family="prose", variant="canonical", gold="A", text="no glyphs"),
        _suite_row(pair_key="p1", family="prose", variant="side_swap", gold="B", text="no glyphs"),
        _suite_row(pair_key="z", family="glyph", variant="canonical", gold="A", text=glyph_zero),
        _suite_row(pair_key="z", family="glyph", variant="side_swap", gold="B", text=glyph_zero),
    ]
    prose = build_pairs(rows, "prose")
    assert len(prose) == 1
    assert prose[0]["pair_key"] == "p1"
    assert prose[0]["net"] > 0
    assert prose[0]["net_sign"] == "+"
    assert prose[0]["cell"] == "concordant"
    assert prose[0]["control_label"] == "A"


def test_pair_scores_splits_decision_from_projection() -> None:
    pair = {
        "pair_key": "p1",
        "gold": "B",
        "swap_gold": "A",
        "net": -4,
        "control_label": "B",
        "base_id": "can",
        "swap_id": "swap",
    }
    predictions = {
        "can": {"probability_b": 0.8},
        "swap": {"probability_b": 0.7},
    }
    outcome = pair_scores(pair, predictions)
    assert outcome is not None
    # Both renderings vote B at 0.5, so the decision is frozen.
    assert outcome["independent_canonical"] == "B"
    assert outcome["independent_swap"] == "B"
    assert outcome["frozen"] is True
    # The projection still reads the score ordering.
    assert outcome["antisym"] == "B"
    assert outcome["antisym_correct"] is True
    # A threshold between the two scores unfreezes the pair.
    unfrozen = pair_scores(pair, predictions, threshold=0.75)
    assert unfrozen is not None
    assert unfrozen["independent_canonical"] == "B"
    assert unfrozen["independent_swap"] == "A"
    assert unfrozen["frozen"] is False


def test_summarise_outcomes_reports_control_and_projection() -> None:
    outcomes = [
        {
            "canonical_correct": True,
            "swap_correct": False,
            "both_correct": False,
            "frozen": True,
            "antisym_correct": True,
            "control_correct": True,
            "projection_margin": 1.0,
            "decision_margin": 2.0,
        }
    ]
    summary = summarise_outcomes(outcomes)
    assert summary["n_pairs"] == 1
    assert summary["antisym_accuracy"] == 1.0
    assert summary["independent_canonical_accuracy"] == 1.0
    assert summary["independent_both_correct"] == 0.0
    assert summary["control_accuracy"] == 1.0
    assert summary["frozen_fraction"] == 1.0


def test_suite_admission_rejects_legacy_versions() -> None:
    with pytest.raises(RelationalReportContractError):
        suite_version_from_summary({"benchmark_version": "v3"})
    assert suite_version_from_summary({"benchmark_version": "v4"}) == "v4"
    assert suite_version_from_summary({"benchmark_version": "v5"}) == "v5"


def test_exact_mirror_table_requires_per_source_rates() -> None:
    summary = {
        "benchmark_version": "v4",
        "sources": {
            "primevul": {
                "ingestion": {"pairs_seen": 827, "single_line_pairs": 0, "single_line_rate": 0.0},
                "eligible_pairs": 797,
                "rejected_non_mirror_pairs": 30,
                "non_mirror_rejection_rate": 0.0363,
                "sampled_pairs": 350,
            }
        },
    }
    table = exact_mirror_rejection_table(summary)
    assert table["sources"]["primevul"]["rejected_non_mirror_pairs"] == 30
    with pytest.raises(RelationalReportContractError):
        exact_mirror_rejection_table({"sources": {}})


def _metric_block() -> dict:
    return {
        "independent_canonical_accuracy": 0.5,
        "independent_both_correct": 0.0,
        "side_swap_equivariance": 0.0,
        "antisym_accuracy": 0.6,
        "control_accuracy": 0.5,
    }


def test_report_contract_fails_closed_on_missing_attachments() -> None:
    payload = {
        "suite_version": "v4",
        "exact_mirror_rejection": {
            "sources": {"primevul": {"rejected_non_mirror_pairs": 30}}
        },
        "families": {
            "prose": {"strongest_control": {"control_accuracy": 0.5}},
            "glyph": {"strongest_control": {"control_accuracy": 0.5}},
        },
        "systems": {
            "2ep": {
                "families": {
                    "prose": {"slices": {"full/discordant": _metric_block()}},
                    "glyph": {"slices": {"full/discordant": _metric_block()}},
                }
            }
        },
    }
    require_relational_report_contract(payload)

    broken = dict(payload)
    broken["families"] = {"prose": {"strongest_control": {}}}
    with pytest.raises(RelationalReportContractError):
        require_relational_report_contract(broken)
