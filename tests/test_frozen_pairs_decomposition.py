from __future__ import annotations

from vrf.frozen_pairs_decomposition import (
    lift_attribution,
    persistence_label,
    product_decomposition,
)
from vrf.surface_features import pair_surface_features, summarise_feature_group


def test_persistence_labels() -> None:
    assert persistence_label(True, True) == "persistently_frozen"
    assert persistence_label(True, False) == "unfroze"
    assert persistence_label(False, True) == "froze"
    assert persistence_label(False, False) == "persistently_unfrozen"


def _pair_outcome(
    key: str, *, frozen: bool, antisym_correct: bool, gold: str = "B"
) -> tuple[dict, dict]:
    pair = {
        "pair_key": key,
        "gold": gold,
        "control_label": "A" if gold == "B" else "B",
        "cell": "discordant",
        "balanced": True,
        "net": -4,
        "net_sign": "-",
    }
    outcome = {
        "frozen": frozen,
        "antisym_correct": antisym_correct,
        "antisym": gold if antisym_correct else ("A" if gold == "B" else "B"),
        "canonical_correct": False,
        "swap_correct": False,
        "both_correct": False,
        "canonical_p_b": 0.9,
        "swap_p_b": 0.8,
        "decision_margin": 2.0,
        "projection_margin": 0.5,
    }
    return pair, outcome


def test_lift_is_carried_by_persistently_frozen_pairs() -> None:
    early = [
        _pair_outcome("p1", frozen=True, antisym_correct=False),
        _pair_outcome("p2", frozen=True, antisym_correct=False),
        _pair_outcome("p3", frozen=True, antisym_correct=True),
        _pair_outcome("p4", frozen=False, antisym_correct=False),
    ]
    late = [
        _pair_outcome("p1", frozen=True, antisym_correct=True),
        _pair_outcome("p2", frozen=True, antisym_correct=True),
        _pair_outcome("p3", frozen=True, antisym_correct=True),
        _pair_outcome("p4", frozen=False, antisym_correct=False),
    ]
    report = lift_attribution(early, late)
    assert report["n_pairs"] == 4
    assert report["lift"] == 0.5
    assert report["groups"]["persistently_frozen"]["n_pairs"] == 3
    assert report["persistently_frozen_share_of_lift"] == 1.0
    assert report["groups"]["persistently_unfrozen"]["lift_contribution"] == 0.0


def test_unfrozen_pairs_can_take_a_share_of_the_lift() -> None:
    early = [
        _pair_outcome("stay", frozen=True, antisym_correct=False),
        _pair_outcome("leave", frozen=True, antisym_correct=False),
    ]
    late = [
        _pair_outcome("stay", frozen=True, antisym_correct=True),
        _pair_outcome("leave", frozen=False, antisym_correct=True),
    ]
    report = lift_attribution(early, late)
    assert report["lift"] == 1.0
    assert report["persistently_frozen_share_of_lift"] == 0.5
    assert report["groups"]["unfroze"]["share_of_lift"] == 0.5


def test_product_decomposition_splits_frozen_mass() -> None:
    early = {
        "antisym_accuracy": 0.4,
        "frozen_fraction": 1.0,
        "antisym_accuracy_on_frozen": 0.4,
        "antisym_accuracy_on_unfrozen": None,
    }
    late = {
        "antisym_accuracy": 0.7,
        "frozen_fraction": 0.8,
        "antisym_accuracy_on_frozen": 0.75,
        "antisym_accuracy_on_unfrozen": 0.5,
    }
    product = product_decomposition(early, late)
    assert product["early_frozen_mass"] == 0.4
    assert product["late_frozen_mass"] == 0.6
    assert product["frozen_mass_delta"] == 0.2


def test_surface_features_are_semantics_free_counts() -> None:
    text = (
        "Task: compare\n"
        "Unified diff:\n"
        "--- Side A\n"
        "+++ Side B\n"
        "@@ -1,2 +1,2 @@\n"
        "-old token\n"
        "+new token extra\n"
    )
    pair = {
        "pair_key": "p1",
        "gold": "A",
        "net": 6,
        "net_sign": "+",
        "cell": "concordant",
        "balanced": True,
        "control_label": "A",
        "dataset": "primevul",
    }
    features = pair_surface_features(pair, text)
    assert features["plus_lines"] == 1
    assert features["minus_lines"] == 1
    assert features["added_token_count"] == 3
    assert features["removed_token_count"] == 2
    assert features["abs_char_net"] == abs(features["char_net"])
    summary = summarise_feature_group([features])
    assert summary["n_pairs"] == 1
    assert summary["n_net_plus"] == 1


def test_published_artifact_matches_locked_curve_if_present() -> None:
    import json
    from pathlib import Path

    from vrf.relational_report_contract import require_relational_report_contract

    path = Path(__file__).resolve().parents[1] / (
        "reports/veripatch_rr_frozen_pairs_decomposition.json"
    )
    if not path.exists():
        return
    payload = json.loads(path.read_text(encoding="utf-8"))
    require_relational_report_contract(payload)
    disc2 = payload["systems"]["2ep"]["families"]["prose"]["slices"]["full/discordant"]
    disc8 = payload["systems"]["8ep"]["families"]["prose"]["slices"]["full/discordant"]
    assert disc2["n_pairs"] == 180
    assert disc2["antisym_accuracy"] == 0.4333
    assert disc8["antisym_accuracy"] == 0.7167
    assert disc2["frozen_fraction"] == 0.9667
    assert disc8["frozen_fraction"] == 0.8778
    assert 0.5111 <= disc2["independent_canonical_accuracy"] <= 0.5500
    assert 0.5111 <= disc8["independent_canonical_accuracy"] <= 0.5500
    assert payload["claim_boundary"]["stop_training"] is True
    assert payload["lift"]["attribution"]["n_pairs"] == 180
    assert payload["lift"]["attribution"]["persistently_frozen_share_of_lift"] == 0.9216
    assert payload["lift"]["attribution"]["lift"] == 0.2833
