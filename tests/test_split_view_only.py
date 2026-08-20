from __future__ import annotations

import json
from pathlib import Path

import pytest

from vrf.split_view_only import (
    AMENDMENT_DATE,
    AMENDMENT_ID,
    ANALYSIS_CODE,
    BOTH_CORRECT_RANDOM_BASELINE,
    DEGENERACY_DELTA_THRESHOLD,
    PREDECLARED_EPOCHS,
    PREDECLARED_MODEL,
    PREDECLARED_OUTPUT_DIR,
    PREDECLARED_SEED,
    PREDECLARED_STEPS,
    PREDECLARED_STEPS_PER_EPOCH,
    PREDECLARED_TRAIN_PAIRS,
    apply_pre_registered_verdict,
    assert_split_view_training_rows,
    both_correct_cap,
    both_correct_from_marginals,
    check_slice_identity,
    marginal_both_correct_baseline,
    finite_number,
    normalize_checkpoint_id,
    text_has_unified_diff_glyphs,
    unfrozen_diagnostic,
    validate_prediction_artifact,
    validate_provenance,
)
from vrf.stats_cluster import wilson_interval

ROOT = Path(__file__).resolve().parents[1]


def _protocol_text() -> str:
    """Protocol markdown with line wrapping collapsed, for substring checks."""

    raw = (ROOT / "docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md").read_text(
        encoding="utf-8"
    )
    return " ".join(raw.split())


# --------------------------------------------------------------------------
# Coherent synthetic slices
# --------------------------------------------------------------------------


def _coherent_slice(
    n: int, n_frozen: int, n_both_correct: int, n_canonical_correct_frozen: int
) -> dict:
    """Build a slice that satisfies the binary mirrored-label identities.

    Frozen pairs contribute exactly one correct side; unfrozen pairs have
    ``canonical_correct == swap_correct``. So::

        n_canonical_correct = n_both_correct + a
        n_swap_correct      = n_both_correct + (n_frozen - a)

    where ``a`` is the number of frozen pairs whose canonical side is correct.
    """

    n_unfrozen = n - n_frozen
    assert 0 <= n_both_correct <= n_unfrozen, "both-correct exceeds the unfrozen cap"
    assert 0 <= n_canonical_correct_frozen <= n_frozen
    n_canonical = n_both_correct + n_canonical_correct_frozen
    n_swap = n_both_correct + (n_frozen - n_canonical_correct_frozen)
    return {
        "n_pairs": n,
        "independent_canonical_accuracy": round(n_canonical / n, 4),
        "independent_canonical_wilson": wilson_interval(n_canonical, n),
        "independent_swap_accuracy": round(n_swap / n, 4),
        "independent_swap_wilson": wilson_interval(n_swap, n),
        "independent_both_correct": round(n_both_correct / n, 4),
        "independent_both_correct_wilson": wilson_interval(n_both_correct, n),
        "frozen_fraction": round(n_frozen / n, 4),
        "exact_counts": {
            "n_pairs": n,
            "n_frozen": n_frozen,
            "n_unfrozen": n_unfrozen,
            "n_canonical_correct": n_canonical,
            "n_swap_correct": n_swap,
            "n_both_correct": n_both_correct,
            "n_both_correct_unfrozen": n_both_correct,
        },
    }


def _good_config() -> dict:
    return {
        "model_name": PREDECLARED_MODEL,
        "output_dir": PREDECLARED_OUTPUT_DIR,
        "require_split_view_only": True,
        "seed": PREDECLARED_SEED,
        "training": {"num_train_epochs": PREDECLARED_EPOCHS},
        "provenance": {
            "predeclared_steps": PREDECLARED_STEPS,
            "training_pairs": PREDECLARED_TRAIN_PAIRS,
        },
    }


def _good_status() -> dict:
    return {
        "status": "ok",
        "model_name": PREDECLARED_MODEL,
        "init_checkpoint": None,
        "train_pairs": PREDECLARED_TRAIN_PAIRS,
        "steps_per_epoch": PREDECLARED_STEPS_PER_EPOCH,
        "epochs": float(PREDECLARED_EPOCHS),
        "seed": PREDECLARED_SEED,
        "smoke": False,
        "output_dir": PREDECLARED_OUTPUT_DIR,
    }


def _good_provenance() -> dict:
    return validate_provenance(_good_config(), _good_status())


# --------------------------------------------------------------------------
# Synthetic suite + predictions for prediction-artifact binding
# --------------------------------------------------------------------------

_VARIANTS = (
    ("glyph", "canonical"),
    ("glyph", "side_swap"),
    ("prose", "prose__canonical"),
    ("prose", "prose__side_swap"),
)


def _suite_rows(n_pairs: int = 6, n_balanced: int = 4) -> list[dict]:
    """A minimal admissible-shaped suite: nonzero char_net, mirrored gold."""

    rows: list[dict] = []
    for index in range(n_pairs):
        key = f"pair-{index}"
        gold = "A" if index % 2 == 0 else "B"
        mirrored = "B" if gold == "A" else "A"
        # Non-zero char_net so build_pairs keeps the pair.
        glyph_text = "Unified diff:\n+aaaaaaaaaa\n-bb\n"
        for family, variant in _VARIANTS:
            rows.append(
                {
                    "id": f"{key}::{family}::{variant}",
                    "pair_key": key,
                    "rendering_family": family,
                    "audit_variant": variant,
                    "gold_riskier_side": gold if "swap" not in variant else mirrored,
                    "polarity_balanced_slice": index < n_balanced,
                    "text": glyph_text
                    if family == "glyph"
                    else "Split-view diff:\nRemoved from Side A:\nbb\n",
                }
            )
    return rows


def _prediction_rows(
    suite_rows: list[dict], *, model_id: str = PREDECLARED_OUTPUT_DIR
) -> list[dict]:
    rows = []
    for index, row in enumerate(suite_rows):
        probability_b = 0.7 if index % 3 else 0.2
        rows.append(
            {
                "id": row["id"],
                "probability_a": 1.0 - probability_b,
                "probability_b": probability_b,
                "model_id": model_id,
            }
        )
    return rows


def _passing_prediction_check() -> dict:
    suite = _suite_rows()
    return validate_prediction_artifact(
        _prediction_rows(suite), suite, checkpoint=PREDECLARED_OUTPUT_DIR
    )


def _payload(
    balanced: dict, full: dict, discordant: dict, provenance: dict | None = None
) -> dict:
    return {
        "provenance_check": _good_provenance() if provenance is None else provenance,
        "prediction_provenance_check": _passing_prediction_check(),
        "systems": {
            "split_view_only": {
                "families": {
                    "prose": {
                        "slices": {
                            "balanced/ALL": balanced,
                            "full/ALL": full,
                            "full/discordant": discordant,
                        }
                    }
                }
            }
        },
    }


def _discordant(canonical: float = 0.52, antisym: float = 0.53) -> dict:
    return {
        "independent_canonical_accuracy": canonical,
        "independent_canonical_wilson": {"point": canonical, "low": 0.45, "high": 0.59},
        "antisym_accuracy": antisym,
    }


# --------------------------------------------------------------------------
# Pre-registration and training-set guards
# --------------------------------------------------------------------------


def test_protocol_locks_budget_and_criteria_before_the_run() -> None:
    protocol = (ROOT / "docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md").read_text(
        encoding="utf-8"
    )
    assert "1,104" in protocol or "1104" in protocol
    assert "**4**" in protocol or "Epochs | **4**" in protocol
    assert "Seed | 7" in protocol
    assert "base model + new LoRA" in protocol.lower() or "fresh LoRA" in protocol
    assert "Do not add a 5th epoch" in protocol
    assert "polarity-balanced / ALL" in protocol or "polarity-balanced" in protocol
    assert "0.8433" in protocol
    assert "stop" in protocol.lower()


def test_amendment_is_recorded_as_post_run_and_does_not_rewrite_pre_registration() -> None:
    protocol = (ROOT / "docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md").read_text(
        encoding="utf-8"
    )
    amendment = protocol.split("## Amendment")[-1]
    assert f"Amendment {AMENDMENT_ID}" in protocol
    assert AMENDMENT_DATE in protocol
    assert "post-run" in amendment.lower()
    assert "after the run" in amendment.lower()
    # The three things the amendment must confess to.
    assert "did not specify" in amendment.lower() or "fixed no numeric null" in amendment.lower()
    assert "0.5" in amendment and "0.25" in amendment
    assert "p_canonical * p_swap" in amendment
    # And the two things it must not do.
    assert "does not authorize further training" in amendment.lower()
    assert "**none.**" in amendment.lower() or "remains `ceiling_holds`" in amendment
    # The pre-registered text above it is intact.
    assert "## Success and failure (locked before looking)" in protocol
    assert protocol.index("## Success and failure") < protocol.index("## Amendment")


def test_config_has_no_glyph_init_and_matches_protocol() -> None:
    config = json.loads(
        (ROOT / "configs/research_split_view_only_qwen3b_v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert "init_checkpoint" not in config
    assert config["require_split_view_only"] is True
    assert config["seed"] == PREDECLARED_SEED
    assert int(config["training"]["num_train_epochs"]) == PREDECLARED_EPOCHS
    assert config["provenance"]["predeclared_steps"] == PREDECLARED_STEPS
    assert config["provenance"]["do_not_extend"] is True


def test_unified_diff_header_is_the_glyph_channel_not_plus_plus_i() -> None:
    split = (
        "Split-view diff from Side A to Side B:\n"
        "Removed from Side A (absent in Side B):\n"
        "++i) {\n"
    )
    glyph = "Unified diff from Side A to Side B:\n--- Side A\n+added\n"
    assert text_has_unified_diff_glyphs(split) is False
    assert text_has_unified_diff_glyphs(glyph) is True


def test_assert_split_view_training_rows_rejects_glyph_layout() -> None:
    ok = [
        {
            "id": "p1",
            "rendering_family": "prose",
            "text": "Split-view diff from Side A to Side B:\nRemoved from Side A:\nfoo\n",
        }
    ]
    assert assert_split_view_training_rows(ok)["glyph_rows"] == 0
    with pytest.raises(ValueError, match="forbids glyph-channel"):
        assert_split_view_training_rows(
            [
                {
                    "id": "bad",
                    "rendering_family": "prose",
                    "text": "Unified diff from Side A to Side B:\n+foo\n",
                }
            ]
        )


# --------------------------------------------------------------------------
# Identities
# --------------------------------------------------------------------------


def test_both_correct_cap_is_the_frozen_complement() -> None:
    """A frozen pair can never be both-correct: gold on the swap is mirrored."""

    assert both_correct_cap(0.8409) == pytest.approx(0.1591)
    assert both_correct_cap(1.0) == 0.0
    assert both_correct_cap(0.0) == 1.0


def test_exact_mirrored_label_identity_holds_on_generated_slices() -> None:
    """both_correct = (canonical + swap - frozen) / 2, exactly."""

    for n, n_frozen, n_both, a in (
        (308, 259, 37, 132),
        (100, 56, 32, 48),
        (300, 150, 108, 78),
        (40, 0, 25, 0),
    ):
        block = _coherent_slice(n, n_frozen, n_both, a)
        derived = both_correct_from_marginals(
            block["independent_canonical_accuracy"],
            block["independent_swap_accuracy"],
            block["frozen_fraction"],
        )
        assert derived == pytest.approx(block["independent_both_correct"], abs=1e-3)
        assert check_slice_identity(block)["consistent"] is True


def test_identity_violation_is_detected() -> None:
    block = _coherent_slice(300, 150, 108, 78)
    block["independent_both_correct"] = 0.90  # incoherent
    check = check_slice_identity(block)
    assert check["checked"] is True
    assert check["consistent"] is False


def test_marginal_baseline_equals_the_random_baseline_only_at_half() -> None:
    assert marginal_both_correct_baseline(0.5, 0.5) == pytest.approx(
        BOTH_CORRECT_RANDOM_BASELINE
    )
    # The case that broke the fixed-0.25 gate: 0.80 * 0.40 == 0.32 exactly.
    assert marginal_both_correct_baseline(0.80, 0.40) == pytest.approx(0.32)
    assert marginal_both_correct_baseline(None, 0.4) is None


def test_unfrozen_diagnostic_uses_exact_counts_not_rounded_rates() -> None:
    """The published balanced/ALL numbers: 37 of 49 unfrozen pairs."""

    diag = unfrozen_diagnostic(49, 37, 308)
    assert diag["point"] == pytest.approx(0.7551, abs=1e-4)
    assert diag["wilson"]["low"] == pytest.approx(0.6191, abs=1e-3)
    assert diag["wilson"]["high"] == pytest.approx(0.8540, abs=1e-3)
    assert diag["unfrozen_coverage"] == pytest.approx(0.1591, abs=1e-4)
    assert "post-hoc" in diag["status"]
    assert unfrozen_diagnostic(0, 0, 308)["point"] is None


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_provenance_accepts_the_pre_declared_run() -> None:
    result = _good_provenance()
    assert result["ok"] is True
    assert result["failures"] == []
    assert result["checks"]["status.total_optimizer_steps"]["observed"] == PREDECLARED_STEPS


@pytest.mark.parametrize(
    "field, value",
    [
        ("status", "failed"),
        ("smoke", True),
        ("seed", 123),
        ("epochs", 5.0),
        ("train_pairs", 4000),
        ("steps_per_epoch", 300),
        ("init_checkpoint", "checkpoints/cls_secure_code_polarity_balanced_scaled_4ep"),
        ("model_name", "Qwen/Qwen2.5-Coder-7B-Instruct"),
        ("output_dir", "checkpoints/somewhere_else"),
    ],
)
def test_provenance_rejects_a_mismatched_run(field: str, value: object) -> None:
    assert _good_provenance()["ok"] is True
    status = _good_status()
    status[field] = value
    result = validate_provenance(_good_config(), status)
    assert result["ok"] is False
    assert result["failures"]


def _verdict_for_provenance(provenance: dict) -> dict:
    return apply_pre_registered_verdict(
        _payload(
            balanced=_coherent_slice(300, 150, 108, 78),
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
            provenance=provenance,
        )
    )


@pytest.mark.parametrize(
    "key",
    [
        "status",
        "smoke",
        "seed",
        "train_pairs",
        "steps_per_epoch",
        "model_name",
        "output_dir",
        "init_checkpoint",
        "epochs",
    ],
)
def test_missing_status_field_fails_closed(key: str) -> None:
    """Absent is not the same as False/None.

    ``smoke`` and ``init_checkpoint`` are the trap cases: ``bool(get(...))``
    and ``get(...) is None`` both silently pass a missing key.
    """

    status = _good_status()
    del status[key]
    result = validate_provenance(_good_config(), status)

    assert result["ok"] is False
    assert any(key in failure for failure in result["failures"])
    assert any("missing" in failure for failure in result["failures"])

    verdict = _verdict_for_provenance(result)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


@pytest.mark.parametrize(
    "path, expected_check",
    [
        (("require_split_view_only",), "config.require_split_view_only"),
        (("seed",), "config.seed"),
        (("model_name",), "config.model_name"),
        (("output_dir",), "config.output_dir"),
        # Deleting a whole nested block must fail through its leaf check.
        (("training",), "config.num_train_epochs"),
        (("training", "num_train_epochs"), "config.num_train_epochs"),
        (("provenance",), "config.predeclared_steps"),
        (("provenance", "predeclared_steps"), "config.predeclared_steps"),
        (("provenance", "training_pairs"), "config.training_pairs"),
    ],
)
def test_missing_config_field_fails_closed(
    path: tuple[str, ...], expected_check: str
) -> None:
    config = _good_config()
    target = config
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]

    result = validate_provenance(config, _good_status())
    assert result["ok"] is False
    assert result["checks"][expected_check]["ok"] is False
    assert result["checks"][expected_check]["present"] is False
    assert any(
        failure.startswith(expected_check) and "missing" in failure
        for failure in result["failures"]
    )

    verdict = _verdict_for_provenance(result)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


@pytest.mark.parametrize("falsey", [None, 0, 0.0, "", [], {}, ()])
def test_smoke_requires_an_exact_boolean_false(falsey: object) -> None:
    """A falsey stand-in must not satisfy the boolean contract."""

    status = _good_status()
    status["smoke"] = falsey
    result = validate_provenance(_good_config(), status)
    assert result["ok"] is False
    assert result["checks"]["status.smoke"]["ok"] is False
    assert any("status.smoke" in failure for failure in result["failures"])

    verdict = _verdict_for_provenance(result)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


def test_smoke_false_and_valid_numerics_still_pass() -> None:
    status = _good_status()
    status["smoke"] = False
    status["epochs"] = 4
    status["steps_per_epoch"] = 276
    result = validate_provenance(_good_config(), status)
    assert result["ok"] is True, result["failures"]
    # 4.0 is equally valid.
    status["epochs"] = 4.0
    assert validate_provenance(_good_config(), status)["ok"] is True


@pytest.mark.parametrize(
    "field, value",
    [
        ("epochs", "oops"),
        ("epochs", float("nan")),
        ("epochs", float("inf")),
        ("epochs", float("-inf")),
        ("epochs", None),
        ("epochs", True),
        ("epochs", [4]),
        ("steps_per_epoch", "oops"),
        ("steps_per_epoch", float("nan")),
        ("steps_per_epoch", float("inf")),
        ("steps_per_epoch", None),
        ("steps_per_epoch", True),
        ("train_pairs", "2208"),
        ("seed", "7"),
    ],
)
def test_malformed_numeric_provenance_fails_without_raising(
    field: str, value: object
) -> None:
    """Malformed numerics must produce a structured failure, never an exception."""

    status = _good_status()
    status[field] = value

    result = validate_provenance(_good_config(), status)  # must not raise
    assert result["ok"] is False
    assert any(f"status.{field}" in failure for failure in result["failures"])

    # The artifact must stay JSON-serializable even with NaN/inf inputs.
    json.dumps(result, allow_nan=False)

    verdict = _verdict_for_provenance(result)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


@pytest.mark.parametrize("field", ["epochs", "steps_per_epoch"])
def test_derived_total_steps_survives_a_malformed_input(field: str) -> None:
    status = _good_status()
    status[field] = "oops"
    result = validate_provenance(_good_config(), status)
    total = result["checks"]["status.total_optimizer_steps"]
    assert total["ok"] is False
    assert any(
        "total_optimizer_steps" in failure and "finite" in failure
        for failure in result["failures"]
    )


def test_booleans_are_not_coerced_into_numbers() -> None:
    assert finite_number(True) is None
    assert finite_number(False) is None
    assert finite_number(float("nan")) is None
    assert finite_number(float("inf")) is None
    assert finite_number("4") is None
    assert finite_number(4) == 4.0
    assert finite_number(4.0) == 4.0

    config = _good_config()
    config["require_split_view_only"] = 1  # truthy, not True
    result = validate_provenance(config, _good_status())
    assert result["ok"] is False
    assert result["checks"]["config.require_split_view_only"]["ok"] is False


def test_config_contract_requires_the_init_checkpoint_key_to_be_absent() -> None:
    """The config declares 'no inherited checkpoint' by omission.

    An explicit null in the *config* is a contract violation, while the train
    *status* must carry an explicit null. The two are recorded separately.
    """

    assert _good_provenance()["ok"] is True

    config = _good_config()
    config["init_checkpoint"] = None
    result = validate_provenance(config, _good_status())
    assert result["ok"] is False
    assert any("init_checkpoint_absent" in failure for failure in result["failures"])
    assert result["checks"]["config.init_checkpoint_absent"]["expected"] == "<key absent>"

    config["init_checkpoint"] = "checkpoints/inherited"
    assert validate_provenance(config, _good_status())["ok"] is False


def test_every_required_field_is_named_in_the_contract() -> None:
    result = _good_provenance()
    for name in result["required_config_fields"] + result["required_status_fields"]:
        assert name in result["checks"], name
        assert result["checks"][name]["ok"] is True, name
        # The absence contract is the one field that must NOT be present.
        expected_present = name != "config.init_checkpoint_absent"
        assert result["checks"][name]["present"] is expected_present, name


def test_missing_provenance_blocks_a_confident_verdict() -> None:
    for config, status in ((None, None), ({}, None), (None, {"status": "ok"})):
        assert validate_provenance(config, status)["ok"] is False

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=_coherent_slice(300, 150, 108, 78),
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
            provenance=validate_provenance(None, None),
        )
    )
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


# --------------------------------------------------------------------------
# Prediction artifact binding
# --------------------------------------------------------------------------


def _prediction_check(rows, suite=None, checkpoint=PREDECLARED_OUTPUT_DIR):
    suite = _suite_rows() if suite is None else suite
    return validate_prediction_artifact(rows, suite, checkpoint=checkpoint)


def test_complete_coherent_prediction_artifact_passes() -> None:
    suite = _suite_rows()
    result = _prediction_check(_prediction_rows(suite), suite)
    assert result["ok"] is True
    assert result["failures"] == []
    assert result["n_prediction_rows"] == result["n_unique_prediction_ids"] == len(suite)
    for family in ("glyph", "prose"):
        cov = result["coverage"][family]
        assert cov["pairs_missing_predictions"] == 0
        assert cov["resolved_full_pairs"] == cov["expected_full_pairs"]
        assert cov["resolved_balanced_pairs"] == cov["expected_balanced_pairs"]


def _assert_indeterminate(prediction_check: dict) -> None:
    payload = _payload(
        balanced=_coherent_slice(300, 150, 108, 78),
        full={"independent_canonical_accuracy": 0.90},
        discordant=_discordant(),
    )
    payload["prediction_provenance_check"] = prediction_check
    verdict = apply_pre_registered_verdict(payload)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["prediction_provenance_ok"] is False
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["stop_training"] is True


def test_one_missing_prediction_is_rejected() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    dropped = rows.pop()
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_required_renderings_absent"] == 1
    assert any("no prediction" in f for f in result["failures"])
    assert any(
        cov["pairs_missing_predictions"] > 0 for cov in result["coverage"].values()
    ), f"dropping {dropped['id']} must leave a pair unresolved"
    _assert_indeterminate(result)


def test_duplicate_prediction_id_is_detected_before_dict_construction() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows.append(dict(rows[0]))  # exact duplicate id
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_prediction_rows"] == len(suite) + 1
    assert result["n_unique_prediction_ids"] == len(suite)
    assert result["duplicate_prediction_ids"] == [rows[0]["id"]]
    assert any("duplicate id" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_mixed_model_ids_are_rejected() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows[0] = {**rows[0], "model_id": "checkpoints/some_other_run"}
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert len(result["model_ids"]) == 2
    assert any("mixed model_id" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_uniform_but_wrong_model_id_is_rejected() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite, model_id="checkpoints/cls_secure_code_unrelated_v9")
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert len(result["model_ids"]) == 1
    assert any("not the requested checkpoint" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_missing_model_id_is_rejected() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows[0] = {**rows[0], "model_id": ""}
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert any("no model_id" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_incomplete_balanced_coverage_is_rejected() -> None:
    """Drop both prose renderings of one balanced pair."""

    suite = _suite_rows()
    rows = [
        row
        for row in _prediction_rows(suite)
        if not (row["id"].startswith("pair-0::prose"))
    ]
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    prose = result["coverage"]["prose"]
    assert prose["resolved_balanced_pairs"] < prose["expected_balanced_pairs"]
    assert prose["pairs_missing_predictions"] == 1
    assert any("balanced_coverage_complete" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_incomplete_full_coverage_is_rejected() -> None:
    """Drop a pair that is outside the balanced slice."""

    suite = _suite_rows(n_pairs=6, n_balanced=4)
    rows = [
        row
        for row in _prediction_rows(suite)
        if not row["id"].startswith("pair-5::")
    ]
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    for family in ("glyph", "prose"):
        cov = result["coverage"][family]
        assert cov["resolved_full_pairs"] < cov["expected_full_pairs"]
    assert any("full_coverage_complete" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_malformed_probability_cannot_silently_shrink_the_eval_set() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows[0] = {**rows[0], "probability_a": None, "probability_b": None}
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_malformed_probabilities"] == 1
    assert any("unusable probability" in f for f in result["failures"])
    _assert_indeterminate(result)

    out_of_range = _prediction_rows(suite)
    out_of_range[1] = {**out_of_range[1], "probability_b": 1.4}
    assert _prediction_check(out_of_range, suite)["n_malformed_probabilities"] == 1


def test_checkpoint_must_match_the_expected_output_dir() -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite, model_id="checkpoints/elsewhere")
    result = _prediction_check(rows, suite, checkpoint="checkpoints/elsewhere")
    assert result["ok"] is False
    assert any("expected_output_dir" in f for f in result["failures"])


def test_checkpoint_identity_is_path_shape_insensitive() -> None:
    assert normalize_checkpoint_id("a\\b\\c/") == "a/b/c"
    assert normalize_checkpoint_id("  a/b  ") == "a/b"
    assert normalize_checkpoint_id(None) == ""
    suite = _suite_rows()
    rows = _prediction_rows(suite, model_id=PREDECLARED_OUTPUT_DIR.replace("/", "\\"))
    assert _prediction_check(rows, suite)["ok"] is True


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_blank_prediction_id_fails_closed(blank: object) -> None:
    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows[0] = {**rows[0], "id": blank}
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_blank_prediction_ids"] == 1
    assert any("missing or empty id" in f for f in result["failures"])
    _assert_indeterminate(result)


def test_extra_prediction_ids_are_recorded_and_rejected() -> None:
    """Policy: the prediction id set must EQUAL the required set."""

    suite = _suite_rows()
    rows = _prediction_rows(suite)
    rows.append(
        {
            "id": "pair-999::prose::prose__canonical",
            "probability_a": 0.5,
            "probability_b": 0.5,
            "model_id": PREDECLARED_OUTPUT_DIR,
        }
    )
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_extra_prediction_ids"] == 1
    assert result["extra_prediction_ids"] == ["pair-999::prose::prose__canonical"]
    assert any("do not correspond" in f for f in result["failures"])
    assert result["checks"]["prediction_id_set_equals_required_set"]["ok"] is False
    assert "strict equality" in result["id_policy"]
    # Coverage alone would not have caught this: every required pair resolves.
    for cov in result["coverage"].values():
        assert cov["pairs_missing_predictions"] == 0
    _assert_indeterminate(result)


def test_duplicate_detection_is_linear_and_precedes_lookup() -> None:
    """Counter-based detection: large duplicate sets stay fast and exact."""

    suite = _suite_rows(n_pairs=30, n_balanced=10)
    rows = _prediction_rows(suite)
    rows.extend(dict(row) for row in rows[:100])
    result = _prediction_check(rows, suite)
    assert result["ok"] is False
    assert result["n_prediction_rows"] == len(rows)
    assert result["n_unique_prediction_ids"] == len(suite)
    expected_dupes = min(100, len(suite))
    assert len(result["duplicate_prediction_ids"]) == min(10, expected_dupes)
    assert any("duplicate id" in f for f in result["failures"])


def test_missing_prediction_provenance_forces_indeterminate() -> None:
    payload = _payload(
        balanced=_coherent_slice(300, 150, 108, 78),
        full={"independent_canonical_accuracy": 0.90},
        discordant=_discordant(),
    )
    payload.pop("prediction_provenance_check", None)
    verdict = apply_pre_registered_verdict(payload)
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["prediction_provenance_ok"] is False


# --------------------------------------------------------------------------
# Adjudication
# --------------------------------------------------------------------------


def test_unexpected_positive_branch_is_reachable() -> None:
    """The protocol's only non-null branch must be able to fire.

    Requires escaping *both* arms of the failure rule: balanced canonical and
    swap each clearing 0.5 from above, and full-set independent beating the
    locked control.
    """

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=_coherent_slice(300, 150, 108, 78),  # canonical .62, swap .60
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
        )
    )
    assert verdict["primary_outcome"] == "unexpected_positive"
    assert verdict["balanced_canonical_clears_chance"] is True
    assert verdict["balanced_swap_clears_chance"] is True
    assert verdict["full_independent_beats_v4_control"] is True
    assert verdict["decision"].startswith("unexpected_positive")
    # Still never a licence to keep training.
    assert verdict["stop_training"] is True


def test_swap_below_chance_cannot_trigger_unexpected_positive() -> None:
    """Canonical 0.80, swap 0.40, both-correct 0.32.

    The fixed-0.25 gate fired here: 0.32 clears 0.25 and canonical clears 0.5.
    But the swap decision is *below* chance and there is no coupling beyond
    the marginals — 0.80 * 0.40 == 0.32 exactly. It is not a usable decision.
    """

    balanced = _coherent_slice(100, 56, 32, 48)
    assert balanced["independent_canonical_accuracy"] == pytest.approx(0.80)
    assert balanced["independent_swap_accuracy"] == pytest.approx(0.40)
    assert balanced["independent_both_correct"] == pytest.approx(0.32)

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=balanced,
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
        )
    )
    assert verdict["balanced_canonical_clears_chance"] is True
    assert verdict["balanced_swap_clears_chance"] is False
    assert verdict["primary_outcome"] == "ceiling_holds"
    assert verdict["unexpected_positive"] is False

    coupling = verdict["balanced_coupling_diagnostic"]
    assert coupling["uncoupled_baseline_p_canonical_times_p_swap"] == pytest.approx(0.32)
    assert coupling["excess_over_uncoupled_baseline"] == pytest.approx(0.0, abs=1e-6)


def test_balanced_clears_but_full_set_fails_the_control_arm() -> None:
    """Protocol failure is an OR. Failing the control arm alone is enough."""

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=_coherent_slice(300, 150, 108, 78),
            full={"independent_canonical_accuracy": 0.60},
            discordant=_discordant(),
        )
    )
    assert verdict["balanced_canonical_clears_chance"] is True
    assert verdict["balanced_swap_clears_chance"] is True
    assert verdict["full_independent_beats_v4_control"] is False
    assert verdict["unexpected_positive"] is False
    assert verdict["primary_outcome"] == "ceiling_holds"


def test_balanced_at_chance_with_a_strong_full_set_is_still_a_failure() -> None:
    """The other arm: balanced CI includes 0.5 but full-set is 0.90.

    This must land on the protocol's failure arm, not 'indeterminate' — the
    inputs are all present and coherent, they simply do not clear.
    """

    balanced = _coherent_slice(308, 259, 37, 132)  # the published slice
    assert balanced["independent_canonical_wilson"]["low"] < 0.5 < balanced[
        "independent_canonical_wilson"
    ]["high"]

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=balanced,
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
        )
    )
    assert verdict["primary_outcome"] == "ceiling_holds"
    assert verdict["outcome_states"]["indeterminate"] is False
    assert verdict["full_independent_beats_v4_control"] is True
    assert verdict["balanced_canonical_clears_chance"] is False


def test_missing_metrics_assert_neither_branch() -> None:
    """Absent data must not be read as evidence for a verdict."""

    verdict = apply_pre_registered_verdict(_payload({}, {}, {}))
    assert verdict["primary_outcome"] == "indeterminate"
    assert verdict["unexpected_positive"] is False
    assert verdict["ceiling_holds"] is False
    assert verdict["decision"].startswith("indeterminate")
    assert verdict["stop_training"] is True
    assert verdict["blocking"]


def test_missing_swap_wilson_alone_forces_indeterminate() -> None:
    balanced = _coherent_slice(300, 150, 108, 78)
    balanced.pop("independent_swap_wilson")
    verdict = apply_pre_registered_verdict(
        _payload(balanced, {"independent_canonical_accuracy": 0.90}, _discordant())
    )
    assert verdict["primary_outcome"] == "indeterminate"
    assert any("swap_wilson" in reason for reason in verdict["blocking"])


def test_inconsistent_slice_forces_indeterminate() -> None:
    balanced = _coherent_slice(300, 150, 108, 78)
    balanced["independent_both_correct"] = 0.90
    verdict = apply_pre_registered_verdict(
        _payload(balanced, {"independent_canonical_accuracy": 0.90}, _discordant())
    )
    assert verdict["primary_outcome"] == "indeterminate"
    assert any("identity" in reason or "both_correct" in reason for reason in verdict["blocking"])


def test_exactly_one_primary_outcome_is_asserted() -> None:
    cases = (
        _payload({}, {}, {}),
        _payload(
            _coherent_slice(300, 150, 108, 78),
            {"independent_canonical_accuracy": 0.90},
            _discordant(),
        ),
        _payload(
            _coherent_slice(308, 259, 37, 132),
            {"independent_canonical_accuracy": 0.5674},
            _discordant(),
        ),
    )
    for payload in cases:
        states = apply_pre_registered_verdict(payload)["outcome_states"]
        assert sum(1 for value in states.values() if value) == 1


def test_degeneracy_is_secondary_and_never_the_primary_outcome() -> None:
    """A strong degeneracy signal must not displace ceiling_holds."""

    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=_coherent_slice(308, 259, 37, 132),
            full={"independent_canonical_accuracy": 0.5674},
            discordant=_discordant(canonical=0.52, antisym=0.72),
        )
    )
    assert verdict["degeneracy_reappears"] is True
    assert verdict["degeneracy_is_secondary"] is True
    assert verdict["primary_outcome"] == "ceiling_holds"
    assert verdict["decision"].startswith("ceiling_holds")


def test_degeneracy_threshold_is_named_and_recorded() -> None:
    """The 0.10 threshold is a secondary descriptive constant, exposed."""

    assert DEGENERACY_DELTA_THRESHOLD == 0.10

    def _verdict(antisym: float) -> dict:
        return apply_pre_registered_verdict(
            _payload(
                balanced=_coherent_slice(308, 259, 37, 132),
                full={"independent_canonical_accuracy": 0.5674},
                discordant=_discordant(canonical=0.52, antisym=antisym),
            )
        )

    just_under = _verdict(0.52 + DEGENERACY_DELTA_THRESHOLD - 0.001)
    assert just_under["degeneracy_reappears"] is False
    at_threshold = _verdict(0.52 + DEGENERACY_DELTA_THRESHOLD)
    assert at_threshold["degeneracy_reappears"] is True

    for verdict in (just_under, at_threshold):
        assert verdict["degeneracy_delta_threshold"] == DEGENERACY_DELTA_THRESHOLD
        assert verdict["degeneracy_observed_delta"] is not None
        assert verdict["primary_outcome"] == "ceiling_holds"
        note = verdict["degeneracy_note"]
        assert "not" in note.lower() and "primary" in note.lower()

    protocol = _protocol_text()
    assert "DEGENERACY_DELTA_THRESHOLD" in protocol
    assert "secondary descriptive threshold" in protocol
    assert "not part of the primary pre-registered" in protocol


def test_old_half_gate_was_restrictive_not_unreachable() -> None:
    """Pin the counterexample so the audit history cannot revert.

    The original gate required both-directions-correct > 0.5. That was
    unjustified and equivariance-dependent, and it rejected the intended
    positive example — but it was NOT universally unreachable. A sufficiently
    equivariant, accurate system clears it.
    """

    # canonical 0.62, swap 0.90, both-correct 0.60, frozen 0.32.
    block = _coherent_slice(300, 96, 180, 6)
    assert block["independent_canonical_accuracy"] == pytest.approx(0.62)
    assert block["independent_swap_accuracy"] == pytest.approx(0.90)
    assert block["independent_both_correct"] == pytest.approx(0.60)
    assert block["frozen_fraction"] == pytest.approx(0.32)
    assert check_slice_identity(block)["consistent"] is True

    # The old gate: canonical clears 0.5 AND both-correct clears 0.5.
    assert block["independent_canonical_wilson"]["low"] > 0.5
    assert block["independent_both_correct"] > 0.5
    assert block["independent_both_correct_wilson"]["low"] > 0.5

    # The current criterion also accepts it — it is a genuine positive.
    verdict = apply_pre_registered_verdict(
        _payload(
            balanced=block,
            full={"independent_canonical_accuracy": 0.90},
            discordant=_discordant(),
        )
    )
    assert verdict["primary_outcome"] == "unexpected_positive"

    # And the amendment must not describe the old gate as unreachable.
    amendment = _protocol_text().split("## Amendment")[-1]
    assert "universally unreachable" in amendment
    assert "overly restrictive" in amendment
    assert "reject the intended positive example" in amendment
    for banned in (
        "was dead code",
        "made the branch **unreachable**",
        "only non-null outcome was dead code",
    ):
        assert banned not in amendment


# --------------------------------------------------------------------------
# Published artifact
# --------------------------------------------------------------------------


def test_published_report_does_not_reopen_locked_curve_if_present() -> None:
    path = ROOT / "reports/SPLIT_VIEW_ONLY_TRAINING_V1.md"
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    assert "does not revive" in text.lower() or "not a continuation" in text.lower()
    assert "stop_training" in text.lower()
    assert "0.8433" in text
    # Bounded claim language: no "produced no relational signal" absolutes.
    assert "did not produce relational signal" not in text
    assert "adjudication label" in text
    json_path = ROOT / "reports/veripatch_rr_split_view_only_training.json"
    if json_path.exists():
        from vrf.relational_report_contract import require_relational_report_contract

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        require_relational_report_contract(payload)
        verdict = payload["verdict"]
        assert verdict["stop_training"] is True
        assert verdict["ceiling_holds"] is True
        assert verdict["primary_outcome"] == "ceiling_holds"
        assert verdict["unexpected_positive"] is False
        assert verdict["provenance_ok"] is True
        assert payload["claim_boundary"]["not_a_continuation_of_the_locked_curve"] is True
        assert payload["amendment"]["status"] == "post-run"
        assert payload["amendment"]["changes_published_outcome"] is False
        assert payload["amendment"]["authorises_further_training"] is False


def test_manifest_detects_an_edited_analysis_file(tmp_path, monkeypatch) -> None:
    """Changing analysis code must surface as a SHA256 mismatch.

    Uses a temporary repo root and a temporary manifest so the real tree is
    never modified. Exercises the shared verifier, not a second hasher.

    The CWD is pinned to the fixture: ``resolve_repo_path`` returns a relative
    path unchanged when it exists relative to the CWD, which would otherwise
    resolve these paths against the real repository.
    """

    from vrf.reproducibility import sha256_file, validate_manifests

    repo = tmp_path / "repo"
    (repo / "src/vrf").mkdir(parents=True)
    (repo / "scripts").mkdir()
    library = repo / "src/vrf/split_view_only.py"
    script = repo / "scripts/analyze_split_view_only_training.py"
    library.write_text("CHANCE = 0.5\n", encoding="utf-8")
    script.write_text("print('analyse')\n", encoding="utf-8")

    manifest = {
        "name": "fixture",
        "artifacts": [
            {
                "role": "analysis_library",
                "path": "src/vrf/split_view_only.py",
                "sha256": sha256_file(library),
                "bytes": library.stat().st_size,
            },
            {
                "role": "analysis_script",
                "path": "scripts/analyze_split_view_only_training.py",
                "sha256": sha256_file(script),
                "bytes": script.stat().st_size,
            },
        ],
    }
    manifest_path = repo / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.chdir(repo)
    clean = validate_manifests([manifest_path], repo_root=repo)
    assert clean["status"] == "ok", clean["checks"]

    # Flip the adjudication constant — exactly the class of edit that would
    # silently change the verdict.
    library.write_text("CHANCE = 0.9\n", encoding="utf-8")
    tampered = validate_manifests([manifest_path], repo_root=repo)
    assert tampered["status"] == "failed"
    bad = [c for c in tampered["checks"] if c["status"] != "ok"]
    assert len(bad) == 1
    assert bad[0]["path"] == "src/vrf/split_view_only.py"
    assert bad[0]["status"] == "mismatch"
    assert "sha256" in bad[0]["message"]


def test_manifest_binds_the_analysis_code() -> None:
    """The real manifest must verify the code, not just the data."""

    path = ROOT / "reproducibility/split_view_only_training_manifest.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))
    bound = {artifact["path"] for artifact in manifest["artifacts"]}
    for _, expected in ANALYSIS_CODE:
        assert expected in bound, f"{expected} is not bound by the manifest"

    roles = {artifact["role"] for artifact in manifest["artifacts"]}
    assert {"analysis_library", "analysis_script", "analysis_dependency"} <= roles


def test_manifest_does_not_present_the_amendment_date_as_creation_time() -> None:
    path = ROOT / "reproducibility/split_view_only_training_manifest.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))

    # created_utc is removed outright; if a timestamp is ever reintroduced it
    # must be generated_utc and must not be the amendment date.
    assert "created_utc" not in manifest
    assert manifest["amendment_date"] == AMENDMENT_DATE
    if "generated_utc" in manifest:
        assert manifest["generated_utc"] != AMENDMENT_DATE

    # No other field may smuggle the amendment date in as a creation time.
    for key, value in manifest.items():
        if isinstance(value, str) and value == AMENDMENT_DATE:
            assert key in {"amendment_date"}, key


def test_reproducibility_manifest_declares_its_publication_blockers() -> None:
    """The manifest must report gitignored inputs, not invent provenance."""

    path = ROOT / "reproducibility/split_view_only_training_manifest.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))

    roles = {artifact["role"] for artifact in manifest["artifacts"]}
    assert {"config", "train_status", "eval_suite", "predictions"} <= roles
    for artifact in manifest["artifacts"] + manifest["generated_artifacts"]:
        assert artifact["sha256"]
        assert artifact["bytes"] > 0

    # Checkpoint weights are never hashed here.
    assert "checkpoint" not in roles
    assert manifest["checkpoint_identity"]["checkpoint"] == PREDECLARED_OUTPUT_DIR

    blockers = manifest["publication_blockers"]
    # Every blocker category must be represented, not just the two easy ones.
    assert {
        "missing_inputs",
        "gitignored_inputs",
        "untracked_inputs",
        "dirty_working_tree",
        "stale_source_commit",
        "missing_analysis_code_hashes",
        "unverified_checkpoint_weights",
    } <= set(blockers)

    # The suite and predictions are gitignored, so this must stay false.
    assert blockers["gitignored_inputs"]
    assert manifest["publication_ready"] is False
    assert manifest["publication_blocking_reasons"]

    # Local reproducibility is a separate, weaker property.
    assert "local_analysis_reproducible" in manifest
    assert manifest["source_commit"]

    assert "--check-only" in manifest["validation_command"]
    assert manifest["expected"]["primary_outcome"] == "ceiling_holds"
    assert manifest["expected"]["stop_training"] is True


def test_published_artifact_is_self_describing() -> None:
    """The JSON alone must carry levels, counts, uncertainty and boundaries."""

    json_path = ROOT / "reports/veripatch_rr_split_view_only_training.json"
    if not json_path.exists():
        return
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    verdict = payload["verdict"]

    levels = verdict["reference_levels"]
    assert levels["independent_canonical_chance"] == 0.5
    assert levels["independent_swap_chance"] == 0.5
    assert levels["both_correct_random_baseline"] == BOTH_CORRECT_RANDOM_BASELINE
    assert "absolute random baseline" in levels["both_correct_random_baseline_note"]
    assert "not a universal null" in levels["both_correct_random_baseline_note"]

    balanced = payload["systems"]["split_view_only"]["families"]["prose"]["slices"][
        "balanced/ALL"
    ]
    counts = balanced["exact_counts"]
    assert counts["n_pairs"] == 308
    assert counts["n_frozen"] == 259
    assert counts["n_unfrozen"] == 49
    assert counts["n_both_correct"] == 37
    assert counts["n_both_correct_unfrozen"] == 37

    unfrozen = balanced["both_correct_given_unfrozen"]
    assert unfrozen["point"] == pytest.approx(0.7551, abs=1e-4)
    assert unfrozen["wilson"]["low"] == pytest.approx(0.6191, abs=1e-3)
    assert unfrozen["wilson"]["high"] == pytest.approx(0.8540, abs=1e-3)
    assert "post-hoc" in unfrozen["status"]

    assert balanced["independent_swap_wilson"] is not None
    assert verdict["balanced_identity_check"]["consistent"] is True
    assert verdict["balanced_coupling_diagnostic"]["status"].startswith("secondary")
    assert payload["provenance_check"]["ok"] is True
    assert any(
        "adjudication label" in boundary for boundary in verdict["claim_boundaries"]
    )
