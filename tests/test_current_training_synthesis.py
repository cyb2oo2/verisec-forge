from __future__ import annotations

from vrf.current_training_synthesis import (
    build_current_training_synthesis,
    required_seed_count,
    summarize_seed_metric,
)


def _payload(seed7: float, seed123: float, delta7: float, delta123: float) -> dict:
    def system(discordant: float, delta: float) -> dict:
        return {
            "population": {
                "acc_concordant": 0.8,
                "acc_discordant": discordant,
                "balanced_accuracy": (0.8 + discordant) / 2,
                "delta_vs_control": delta,
            }
        }

    return {
        "families": {
            "prose": {
                "systems": {
                    "baseline_antisym": system(seed7, delta7),
                    "repaired_antisym": system(seed123, delta123),
                }
            }
        }
    }


def test_seed_summary_uses_seed_as_unit_of_inference() -> None:
    summary = summarize_seed_metric([0.4, 0.6])
    assert summary["n_seeds"] == 2
    assert summary["mean"] == 0.5
    assert summary["student_t_95_half_width"] > 1.0


def test_required_seed_count_accounts_for_small_sample_t_penalty() -> None:
    assert required_seed_count(0.055, 0.05) == 8
    assert required_seed_count(0.055, 0.025) == 22


def test_synthesis_keeps_claims_bounded_and_reports_precision() -> None:
    payloads = {
        "1.5B bf16": _payload(0.44, 0.36, 0.15, 0.13),
        "7B nf4": _payload(0.52, 0.52, 0.19, 0.18),
        "3B bf16": _payload(0.63, 0.57, 0.23, 0.20),
    }
    result = build_current_training_synthesis(
        matched_compute_payloads=payloads,
        supply_payloads={"v1": payloads["3B bf16"], "v2": payloads["3B bf16"]},
    )
    assert result["seed_precision"]["unit_of_inference"] == "training seed"
    assert result["seed_precision"]["projected_95_half_width_at_3_seeds"] > 0.1
    assert "two-seed" in result["matched_compute"]["boundary"]
    assert result["matched_compute"]["closest_7b_3b_same_seed_gap"] > 0
    assert "not evidence" in result["overall_conclusion"]
    supply = result["discordant_supply_control"]
    assert supply["largest_between_arm_mean_gap"] == 0.0
    assert "slightly above the smallest" in supply["boundary"]
