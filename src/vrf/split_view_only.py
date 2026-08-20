"""Arc 2 Q1: split-view-only training guards and verdict.

Glyph-free training is a *channel* test. The pre-registered rules live in
``docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md`` and are applied here so the
report builder cannot quietly rewrite them after looking at the numbers.

Adjudication estimand (Amendment A, 2026-08-18 — see the protocol doc)
    The pre-registered phrase "both-directions-correct also leaves chance"
    did not fix a numeric null. It is operationalised here as a **usable
    independent decision**: the per-rendering decision must clear chance on
    *both* renderings, each with pair-level uncertainty. Joint both-correct
    stays as a reported diagnostic, not as the gate.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Mapping, Sequence

from vrf.frozen_pairs_decomposition import resolve_pairs
from vrf.pair_decision import build_pairs
from vrf.stats_cluster import wilson_interval

UNIFIED_DIFF_MARKERS = (
    "Unified diff from Side A to Side B:",
    "Unified diff:",
)

PREDECLARED_EPOCHS = 4
PREDECLARED_STEPS = 1104
PREDECLARED_STEPS_PER_EPOCH = 276
PREDECLARED_SEED = 7
PREDECLARED_TRAIN_PAIRS = 2208
PREDECLARED_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"
PREDECLARED_OUTPUT_DIR = "checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1"

CHANCE = 0.5

# The accuracy of two *independent fair-coin* decisions, both correct: 0.5 * 0.5.
# This is an absolute random baseline and nothing more. It is NOT a universal
# chance rate and NOT the null for this system:
#
#   * The uncoupled baseline for both-correct is the product of the observed
#     marginals, ``p_canonical * p_swap``. It equals 0.25 only when both
#     marginals are exactly 0.5.
#   * ``both_correct <= 1 - frozen_fraction`` is an identity, so on a system
#     with a high frozen share the column is capped far below 0.25 before any
#     accuracy is measured. Falling below 0.25 is therefore entailed, not
#     evidence of anything.
#
# It is reported for orientation only and is never the adjudication gate.
BOTH_CORRECT_RANDOM_BASELINE = 0.25

V4_FULL_CONTROL = 0.8502
LOCKED_PROSE_CONTROL = 0.8433

# Rounded aggregates are stored to 4dp; the identity check must tolerate that.
IDENTITY_TOLERANCE = 1e-3

# Secondary descriptive threshold for the degeneracy flag: the gap between the
# pair-level projection and the per-rendering decision on the full discordant
# cell. It is NOT part of the primary pre-registered success/failure
# adjudication and never modifies the primary outcome.
DEGENERACY_DELTA_THRESHOLD = 0.10

AMENDMENT_ID = "A"
# The date Amendment A was written. This is protocol history — it is NOT a
# manifest creation time and must never be presented as one.
AMENDMENT_DATE = "2026-08-18"

# Code whose content determines the adjudication. Bound by hash in both the
# report JSON and the reproducibility manifest, with roles assigned by the
# manifest builder.
ANALYSIS_CODE: tuple[tuple[str, str], ...] = (
    ("analysis_library", "src/vrf/split_view_only.py"),
    ("analysis_script", "scripts/analyze_split_view_only_training.py"),
    ("analysis_script", "scripts/build_split_view_only_manifest.py"),
    ("analysis_dependency", "src/vrf/pair_decision.py"),
    ("analysis_dependency", "src/vrf/frozen_pairs_decomposition.py"),
    ("analysis_dependency", "src/vrf/stats_cluster.py"),
    ("analysis_dependency", "src/vrf/relational_report_contract.py"),
    ("analysis_dependency", "src/vrf/reproducibility.py"),
)

ANALYSIS_CODE_PATHS: tuple[str, ...] = tuple(path for _, path in ANALYSIS_CODE)


class _Missing:
    """Sentinel distinguishing an absent key from a present ``None``/``False``."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "<missing>"


MISSING = _Missing()


# --------------------------------------------------------------------------
# Identities
# --------------------------------------------------------------------------


def both_correct_cap(frozen_fraction: float) -> float:
    """Upper bound on ``both_directions_correct`` implied by the frozen share.

    A *frozen* pair is one where the argmax returns the same side on both
    renderings. Gold on the swap is the mirror of gold on the canonical, so
    exactly one of the two is correct and the pair can never be both-correct.
    Hence ``both_correct <= 1 - frozen_fraction``, as an identity.
    """

    return max(0.0, 1.0 - float(frozen_fraction))


def both_correct_from_marginals(
    canonical_accuracy: float, swap_accuracy: float, frozen_fraction: float
) -> float:
    """Exact binary mirrored-label identity.

    ``both_correct = (canonical_accuracy + swap_accuracy - frozen_fraction) / 2``

    Frozen pairs contribute exactly one correct side (gold is mirrored, the
    model is not), so ``c + s = 1`` and ``both = 0``. Unfrozen pairs have
    ``c == s`` (the model's two answers are mirrored too), so ``c + s = 2*both``.
    Summing both cases gives the identity.
    """

    return (float(canonical_accuracy) + float(swap_accuracy) - float(frozen_fraction)) / 2.0


def marginal_both_correct_baseline(
    canonical_accuracy: float | None, swap_accuracy: float | None
) -> float | None:
    """Uncoupled baseline for both-correct: the product of the marginals.

    This is the quantity a coupling diagnostic must be compared against.
    ``BOTH_CORRECT_RANDOM_BASELINE`` is its value in the special case where
    both marginals are exactly 0.5.
    """

    if canonical_accuracy is None or swap_accuracy is None:
        return None
    return float(canonical_accuracy) * float(swap_accuracy)


def check_slice_identity(block: Mapping[str, Any]) -> dict[str, Any]:
    """Verify the mirrored-label identity on one reported slice."""

    canonical = block.get("independent_canonical_accuracy")
    swap = block.get("independent_swap_accuracy")
    frozen = block.get("frozen_fraction")
    both = block.get("independent_both_correct")
    if None in (canonical, swap, frozen, both):
        return {
            "checked": False,
            "consistent": None,
            "reason": "missing one of canonical/swap/frozen/both",
        }
    expected = both_correct_from_marginals(canonical, swap, frozen)
    residual = abs(float(both) - expected)
    return {
        "checked": True,
        "consistent": residual <= IDENTITY_TOLERANCE,
        "identity": "both_correct = (canonical + swap - frozen) / 2",
        "expected_both_correct": round(expected, 6),
        "observed_both_correct": float(both),
        "residual": round(residual, 6),
        "tolerance": IDENTITY_TOLERANCE,
    }


# --------------------------------------------------------------------------
# Training-set guard
# --------------------------------------------------------------------------


def text_has_unified_diff_glyphs(text: str) -> bool:
    """True when a rendering still presents the interleaved ``+``/``-`` channel.

    Source-code tokens such as ``++i`` are not a unified-diff header and do
    not count. The training-set contract is the *layout*, not the absence of
    plus characters inside C.
    """

    return any(marker in text for marker in UNIFIED_DIFF_MARKERS)


def assert_split_view_training_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Fail loud if any training row still carries the glyph layout."""

    n = 0
    glyph_rows: list[str] = []
    families: dict[str, int] = {}
    for row in rows:
        n += 1
        family = str(row.get("rendering_family") or "")
        families[family] = families.get(family, 0) + 1
        if family == "glyph" or text_has_unified_diff_glyphs(str(row.get("text") or "")):
            glyph_rows.append(str(row.get("id") or row.get("pair_key")))
    if glyph_rows:
        sample = ", ".join(glyph_rows[:5])
        raise ValueError(
            "split-view-only training forbids glyph-channel rows; "
            f"found {len(glyph_rows)} (e.g. {sample})"
        )
    if families and set(families) - {"prose"}:
        raise ValueError(
            f"split-view-only training requires rendering_family=prose; got {families}"
        )
    return {"n_rows": n, "families": families, "glyph_rows": 0}


# --------------------------------------------------------------------------
# Provenance: fail closed on the training budget
# --------------------------------------------------------------------------


def _dig(mapping: Mapping[str, Any], *keys: str) -> Any:
    """Fetch a nested key, returning ``MISSING`` if any level is absent."""

    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return MISSING
        current = current[key]
    return current


def finite_number(value: Any) -> float | None:
    """``float(value)`` when it is a finite, non-boolean number; else ``None``.

    Booleans are rejected on type grounds: ``True == 1`` would otherwise let a
    boolean satisfy an integer contract. NaN and infinity are rejected as
    non-finite. Strings are never coerced — a malformed value is a provenance
    failure, not something to parse hopefully.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if math.isnan(number) or math.isinf(number):
        return None
    return number


# Required field tables: (check name, key path, expected value, kind).
#
# kind:
#   "exact"      -- equality against a string/scalar
#   "number"     -- finite, non-boolean number equal to the expected value
#   "is_true"    -- identity with True (a real boolean, not a truthy value)
#   "is_false"   -- identity with False (not None/0/""/[])
#   "is_none"    -- identity with None (present, explicitly null)
REQUIRED_CONFIG_FIELDS: tuple[tuple[str, tuple[str, ...], Any, str], ...] = (
    ("config.require_split_view_only", ("require_split_view_only",), True, "is_true"),
    ("config.seed", ("seed",), PREDECLARED_SEED, "number"),
    (
        "config.num_train_epochs",
        ("training", "num_train_epochs"),
        PREDECLARED_EPOCHS,
        "number",
    ),
    (
        "config.predeclared_steps",
        ("provenance", "predeclared_steps"),
        PREDECLARED_STEPS,
        "number",
    ),
    (
        "config.training_pairs",
        ("provenance", "training_pairs"),
        PREDECLARED_TRAIN_PAIRS,
        "number",
    ),
    ("config.model_name", ("model_name",), PREDECLARED_MODEL, "exact"),
    ("config.output_dir", ("output_dir",), PREDECLARED_OUTPUT_DIR, "exact"),
)

# ``smoke`` and ``init_checkpoint`` are listed here so an absent key fails even
# though the expected value is False / None, and are matched by *identity* so a
# falsey stand-in (0, "", [], None) cannot satisfy them.
REQUIRED_STATUS_FIELDS: tuple[tuple[str, str, Any, str], ...] = (
    ("status.status", "status", "ok", "exact"),
    ("status.smoke", "smoke", False, "is_false"),
    ("status.seed", "seed", PREDECLARED_SEED, "number"),
    ("status.train_pairs", "train_pairs", PREDECLARED_TRAIN_PAIRS, "number"),
    (
        "status.steps_per_epoch",
        "steps_per_epoch",
        PREDECLARED_STEPS_PER_EPOCH,
        "number",
    ),
    ("status.model_name", "model_name", PREDECLARED_MODEL, "exact"),
    ("status.output_dir", "output_dir", PREDECLARED_OUTPUT_DIR, "exact"),
    ("status.init_checkpoint", "init_checkpoint", None, "is_none"),
)


def validate_provenance(
    config: Mapping[str, Any] | None, status: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Check the run that produced the predictions is the pre-declared one.

    Every required field is validated by *key membership*, not by value
    coercion. A field whose expected value is ``False`` or ``None`` still
    fails when the key is absent — ``dict.get`` cannot distinguish those, so
    the ``MISSING`` sentinel is used throughout.

    A missing or mismatched field is a hard block on a confident verdict: the
    analyser must not adjudicate a checkpoint it cannot identify.
    """

    failures: list[str] = []
    checks: dict[str, Any] = {}

    def _record(
        name: str,
        observed: Any,
        expected: Any,
        ok: bool,
        *,
        reason: str | None = None,
    ) -> None:
        serializable = None if observed is MISSING else observed
        if isinstance(serializable, float) and (
            math.isnan(serializable) or math.isinf(serializable)
        ):
            # NaN/Infinity are not valid JSON; keep the artifact loadable.
            serializable = repr(serializable)
        checks[name] = {
            "observed": serializable,
            "expected": expected,
            "present": observed is not MISSING,
            "ok": ok,
        }
        if not ok:
            if observed is MISSING:
                failures.append(f"{name}: required field is missing")
            elif reason:
                failures.append(f"{name}: {reason} (got {serializable!r})")
            else:
                failures.append(f"{name}: expected {expected!r}, got {serializable!r}")

    def _check(name: str, observed: Any, expected: Any, kind: str = "exact") -> None:
        """Type-strict field check. Never raises on a malformed value."""

        if observed is MISSING:
            _record(name, observed, expected, False)
            return
        if kind == "number":
            number = finite_number(observed)
            _record(
                name,
                observed,
                expected,
                number is not None and number == float(expected),
                reason=(
                    "expected a finite non-boolean number "
                    f"equal to {expected!r}"
                ),
            )
        elif kind == "is_true":
            _record(
                name, observed, expected, observed is True, reason="expected exactly True"
            )
        elif kind == "is_false":
            _record(
                name,
                observed,
                expected,
                observed is False,
                reason="expected exactly False (a boolean, not a falsey value)",
            )
        elif kind == "is_none":
            _record(
                name,
                observed,
                expected,
                observed is None,
                reason="expected an explicit null",
            )
        else:
            _record(name, observed, expected, observed == expected)

    if not isinstance(config, Mapping):
        failures.append("config: missing")
        checks["config"] = {
            "observed": None,
            "expected": "object",
            "present": False,
            "ok": False,
        }
    else:
        for name, path, expected, kind in REQUIRED_CONFIG_FIELDS:
            _check(name, _dig(config, *path), expected, kind)
        # The config contract expects the key to be ABSENT: this run must not
        # inherit any checkpoint, and the config declares that by omission.
        # (The train status, by contrast, must carry an explicit null.)
        init = _dig(config, "init_checkpoint")
        checks["config.init_checkpoint_absent"] = {
            "observed": None if init is MISSING else init,
            "expected": "<key absent>",
            "present": init is not MISSING,
            "ok": init is MISSING,
            "contract": "key must be absent from the config",
        }
        if init is not MISSING:
            failures.append(
                "config.init_checkpoint_absent: key must be absent from the "
                f"config, got {init!r}"
            )

    if not isinstance(status, Mapping):
        failures.append("train_status: missing")
        checks["train_status"] = {
            "observed": None,
            "expected": "object",
            "present": False,
            "ok": False,
        }
    else:
        for name, key, expected, kind in REQUIRED_STATUS_FIELDS:
            _check(name, _dig(status, key), expected, kind)

        epochs = _dig(status, "epochs")
        _check("status.epochs", epochs, PREDECLARED_EPOCHS, "number")

        # Derived only from values that already parsed as finite numbers, so a
        # malformed epochs/steps_per_epoch cannot raise here.
        steps_per_epoch = _dig(status, "steps_per_epoch")
        epochs_number = None if epochs is MISSING else finite_number(epochs)
        steps_number = (
            None if steps_per_epoch is MISSING else finite_number(steps_per_epoch)
        )
        if epochs_number is None or steps_number is None:
            _record(
                "status.total_optimizer_steps",
                MISSING,
                PREDECLARED_STEPS,
                False,
            )
            failures[-1] = (
                "status.total_optimizer_steps: cannot be derived — "
                "epochs or steps_per_epoch is missing or not a finite number"
            )
        else:
            total = int(round(steps_number * epochs_number))
            _record(
                "status.total_optimizer_steps",
                total,
                PREDECLARED_STEPS,
                total == PREDECLARED_STEPS,
            )

    return {
        "ok": not failures,
        "failures": failures,
        "checks": checks,
        "required_config_fields": [field[0] for field in REQUIRED_CONFIG_FIELDS]
        + ["config.init_checkpoint_absent"],
        "required_status_fields": [field[0] for field in REQUIRED_STATUS_FIELDS]
        + ["status.epochs", "status.total_optimizer_steps"],
        "note": (
            "Validated by key membership, not value coercion: a required field "
            "whose expected value is False or None still fails when absent. Any "
            "missing or mismatched field forces 'indeterminate'."
        ),
    }


# --------------------------------------------------------------------------
# Prediction artifact: bind the evaluated rows to the validated run
# --------------------------------------------------------------------------


def normalize_checkpoint_id(value: Any) -> str:
    """Path-shape-insensitive checkpoint identity."""

    if value is None:
        return ""
    return str(value).replace("\\", "/").strip().rstrip("/")


def _usable_probability_b(prediction: Mapping[str, Any]) -> float | None:
    """Mirror ``pair_decision._probability_b`` with a validity check.

    Returns ``None`` for anything the pair builder would silently drop.
    """

    value = prediction.get("probability_b")
    if value is None:
        value = prediction.get("probability_a")
        if value is None:
            return None
        try:
            value = 1.0 - float(value)
        except (TypeError, ValueError):
            return None
    try:
        probability = float(value)
    except (TypeError, ValueError):
        return None
    if probability != probability or probability in (float("inf"), float("-inf")):
        return None
    if not 0.0 <= probability <= 1.0:
        return None
    return probability


def validate_prediction_artifact(
    prediction_rows: Sequence[Mapping[str, Any]],
    suite_rows: Sequence[Mapping[str, Any]],
    *,
    checkpoint: str,
    expected_output_dir: str = PREDECLARED_OUTPUT_DIR,
) -> dict[str, Any]:
    """Bind the prediction artifact to the validated run.

    Expected pair counts are *derived from the loaded admissible suite*, never
    hard-coded. Duplicate ids are detected on the raw row list, before any
    dictionary construction could silently collapse them.
    """

    failures: list[str] = []
    checks: dict[str, Any] = {}

    def _record(name: str, ok: bool, detail: Any = None, message: str | None = None) -> None:
        checks[name] = {"ok": ok, "detail": detail}
        if not ok:
            failures.append(message or f"{name}: failed ({detail!r})")

    rows = list(prediction_rows)

    # An absent/empty id cannot be bound to a suite rendering at all.
    blank_id_positions = [
        index
        for index, row in enumerate(rows)
        if row.get("id") is None or not str(row.get("id")).strip()
    ]
    _record(
        "prediction_ids_present",
        not blank_id_positions,
        {"n_blank": len(blank_id_positions), "row_positions": blank_id_positions[:5]},
        f"prediction_ids_present: {len(blank_id_positions)} row(s) have a missing "
        "or empty id",
    )

    ids = [str(row.get("id")).strip() for row in rows]
    unique_ids = set(ids)

    # Duplicates first: dict construction would overwrite them silently.
    # Counter keeps this linear rather than a quadratic list.count() scan.
    counts = Counter(ids)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    _record(
        "prediction_ids_unique",
        not duplicates,
        {"n_rows": len(rows), "n_unique": len(unique_ids), "duplicates": duplicates[:10]},
        f"prediction_ids_unique: {len(ids) - len(unique_ids)} duplicate id(s), "
        f"e.g. {duplicates[:3]}",
    )

    missing_model_id = [key for key, row in zip(ids, rows) if not str(row.get("model_id") or "").strip()]
    _record(
        "prediction_model_id_present",
        not missing_model_id,
        {"n_missing": len(missing_model_id), "examples": missing_model_id[:5]},
        f"prediction_model_id_present: {len(missing_model_id)} row(s) have no model_id",
    )

    model_ids = sorted({str(row.get("model_id") or "").strip() for row in rows if str(row.get("model_id") or "").strip()})
    _record(
        "prediction_model_id_uniform",
        len(model_ids) <= 1,
        {"model_ids": model_ids},
        f"prediction_model_id_uniform: mixed model_id values {model_ids}",
    )

    normalized_checkpoint = normalize_checkpoint_id(checkpoint)
    normalized_expected = normalize_checkpoint_id(expected_output_dir)
    normalized_model = normalize_checkpoint_id(model_ids[0]) if len(model_ids) == 1 else ""
    _record(
        "prediction_model_id_matches_checkpoint",
        bool(normalized_model) and normalized_model == normalized_checkpoint,
        {"model_id": normalized_model, "checkpoint": normalized_checkpoint},
        "prediction_model_id_matches_checkpoint: predictions were produced by "
        f"{normalized_model!r}, not the requested checkpoint {normalized_checkpoint!r}",
    )
    _record(
        "checkpoint_matches_expected_output_dir",
        normalized_checkpoint == normalized_expected,
        {"checkpoint": normalized_checkpoint, "expected": normalized_expected},
        f"checkpoint_matches_expected_output_dir: {normalized_checkpoint!r} != "
        f"{normalized_expected!r}",
    )

    # Build the lookup only after the duplicate check.
    predictions: dict[str, Mapping[str, Any]] = {}
    for key, row in zip(ids, rows):
        predictions.setdefault(key, row)

    # Every required suite rendering must have a usable prediction.
    required_ids = [
        str(row["id"])
        for row in suite_rows
        if (row.get("rendering_family"), row.get("audit_variant"))
        in (
            ("glyph", "canonical"),
            ("glyph", "side_swap"),
            ("prose", "prose__canonical"),
            ("prose", "prose__side_swap"),
        )
    ]
    required_set = set(required_ids)
    absent = [key for key in required_ids if key not in predictions]
    # Policy: the prediction id set must EQUAL the required suite-rendering set.
    # Extras are not silently ignored — an unrelated or mixed prediction file is
    # exactly what this check exists to catch.
    extras = sorted(key for key in unique_ids if key and key not in required_set)
    malformed = [
        key
        for key in required_ids
        if key in predictions and _usable_probability_b(predictions[key]) is None
    ]
    _record(
        "all_required_renderings_predicted",
        not absent,
        {"n_required": len(required_ids), "n_absent": len(absent), "examples": absent[:5]},
        f"all_required_renderings_predicted: {len(absent)} suite rendering(s) have "
        "no prediction",
    )
    _record(
        "no_extra_prediction_ids",
        not extras,
        {"n_extra": len(extras), "examples": extras[:5]},
        f"no_extra_prediction_ids: {len(extras)} prediction id(s) do not "
        f"correspond to any required suite rendering, e.g. {extras[:3]}",
    )
    _record(
        "prediction_id_set_equals_required_set",
        not absent and not extras,
        {"n_required": len(required_set), "n_predicted": len(unique_ids)},
        "prediction_id_set_equals_required_set: the prediction id set differs "
        f"from the required suite-rendering set ({len(absent)} absent, "
        f"{len(extras)} extra)",
    )
    _record(
        "no_malformed_probabilities",
        not malformed,
        {"n_malformed": len(malformed), "examples": malformed[:5]},
        f"no_malformed_probabilities: {len(malformed)} prediction(s) carry an "
        "unusable probability and would be silently dropped",
    )

    # Coverage, with expectations derived from the suite itself.
    coverage: dict[str, Any] = {}
    for family in ("glyph", "prose"):
        pairs = build_pairs(suite_rows, family)
        resolved, dropped = resolve_pairs(pairs, predictions)
        expected_full = len(pairs)
        expected_balanced = sum(1 for pair in pairs if pair["balanced"])
        resolved_full = len(resolved)
        resolved_balanced = sum(1 for pair, _ in resolved if pair["balanced"])
        coverage[family] = {
            "expected_full_pairs": expected_full,
            "resolved_full_pairs": resolved_full,
            "expected_balanced_pairs": expected_balanced,
            "resolved_balanced_pairs": resolved_balanced,
            "pairs_missing_predictions": dropped,
        }
        _record(
            f"{family}_pairs_missing_predictions_zero",
            dropped == 0,
            {"pairs_missing_predictions": dropped},
            f"{family}_pairs_missing_predictions_zero: {dropped} pair(s) lack a "
            "complete canonical/swap prediction pair",
        )
        _record(
            f"{family}_full_coverage_complete",
            resolved_full == expected_full,
            {"expected": expected_full, "resolved": resolved_full},
            f"{family}_full_coverage_complete: evaluated {resolved_full} of "
            f"{expected_full} full-slice pairs",
        )
        _record(
            f"{family}_balanced_coverage_complete",
            resolved_balanced == expected_balanced,
            {"expected": expected_balanced, "resolved": resolved_balanced},
            f"{family}_balanced_coverage_complete: evaluated {resolved_balanced} "
            f"of {expected_balanced} balanced-slice pairs",
        )

    return {
        "ok": not failures,
        "failures": failures,
        "checks": checks,
        "n_prediction_rows": len(rows),
        "n_unique_prediction_ids": len(unique_ids),
        "duplicate_prediction_ids": duplicates[:10],
        "model_ids": model_ids,
        "normalized_model_id": normalized_model,
        "normalized_checkpoint": normalized_checkpoint,
        "expected_output_dir": normalized_expected,
        "n_required_renderings": len(required_ids),
        "n_required_renderings_absent": len(absent),
        "n_extra_prediction_ids": len(extras),
        "extra_prediction_ids": extras[:10],
        "n_blank_prediction_ids": len(blank_id_positions),
        "n_malformed_probabilities": len(malformed),
        "coverage": coverage,
        "id_policy": (
            "strict equality: the set of prediction ids must equal the set of "
            "required suite-rendering ids. Extras are reported and fail the "
            "check; they are never silently ignored."
        ),
        "note": (
            "Expected pair counts are derived from the loaded admissible suite, "
            "not hard-coded. Duplicate ids are detected on the raw row list "
            "before dictionary construction, in linear time. Any failure forces "
            "'indeterminate'."
        ),
    }


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


def _wilson_flags(flags: Sequence[bool]) -> dict[str, Any] | None:
    if not flags:
        return None
    return wilson_interval(sum(1 for flag in flags if flag), len(flags))


def _ci_includes(interval: Mapping[str, Any] | None, value: float = CHANCE) -> bool | None:
    if interval is None or interval.get("low") is None or interval.get("high") is None:
        return None
    return float(interval["low"]) <= value <= float(interval["high"])


def _clears_from_above(
    point: float | None, interval: Mapping[str, Any] | None, level: float = CHANCE
) -> bool | None:
    """True when the point is above ``level`` and the CI excludes it below.

    ``None`` when the metric or its interval is absent — never guessed.
    """

    if point is None or interval is None or interval.get("low") is None:
        return None
    return float(point) > float(level) and float(interval["low"]) > float(level)


def apply_pre_registered_verdict(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Adjudicate one trained system against the protocol.

    Exactly one primary outcome is asserted:

    ``indeterminate``
        A required metric is missing, or a reported slice violates the
        mirrored-label identity, or training provenance does not match the
        pre-declared budget.
    ``unexpected_positive``
        Balanced canonical *and* balanced swap accuracy each clear 0.5 from
        above, *and* full-set independent beats the locked control. Both arms
        of the protocol's failure rule must be escaped.
    ``ceiling_holds``
        Otherwise — the protocol's failure arm: balanced evidence stays at
        chance OR full-set independent does not beat the control.

    ``degeneracy_reappears`` is a secondary mechanistic flag. It never
    replaces the primary outcome.
    """

    families = (payload.get("systems") or {}).get("split_view_only") or {}
    family_map = families.get("families") or {}
    prose = (family_map.get("prose") or {}).get("slices") or {}
    balanced = prose.get("balanced/ALL") or {}
    full = prose.get("full/ALL") or {}
    disc = prose.get("full/discordant") or {}

    balanced_canonical = balanced.get("independent_canonical_accuracy")
    balanced_canonical_wilson = balanced.get("independent_canonical_wilson")
    balanced_swap = balanced.get("independent_swap_accuracy")
    balanced_swap_wilson = balanced.get("independent_swap_wilson")
    balanced_both = balanced.get("independent_both_correct")
    balanced_frozen = balanced.get("frozen_fraction")
    full_indep = full.get("independent_canonical_accuracy")

    canonical_clears = _clears_from_above(balanced_canonical, balanced_canonical_wilson)
    swap_clears = _clears_from_above(balanced_swap, balanced_swap_wilson)
    full_beats_control = (
        None if full_indep is None else float(full_indep) > V4_FULL_CONTROL
    )

    identity = check_slice_identity(balanced)
    provenance = payload.get("provenance_check") or {}
    provenance_ok = bool(provenance.get("ok")) if provenance else False
    prediction_provenance = payload.get("prediction_provenance_check") or {}
    prediction_provenance_ok = (
        bool(prediction_provenance.get("ok")) if prediction_provenance else False
    )

    missing = [
        name
        for name, value in (
            ("balanced.independent_canonical_accuracy", balanced_canonical),
            ("balanced.independent_canonical_wilson", balanced_canonical_wilson),
            ("balanced.independent_swap_accuracy", balanced_swap),
            ("balanced.independent_swap_wilson", balanced_swap_wilson),
            ("balanced.independent_both_correct", balanced_both),
            ("balanced.frozen_fraction", balanced_frozen),
            ("full.independent_canonical_accuracy", full_indep),
        )
        if value is None
    ]
    blocking: list[str] = list(missing)
    if identity.get("checked") and identity.get("consistent") is False:
        blocking.append(
            "balanced slice violates both_correct = (canonical + swap - frozen)/2 "
            f"(residual {identity.get('residual')})"
        )
    if not provenance_ok:
        blocking.extend(
            f"provenance: {reason}" for reason in (provenance.get("failures") or ["not checked"])
        )
    if not prediction_provenance_ok:
        blocking.extend(
            f"prediction provenance: {reason}"
            for reason in (prediction_provenance.get("failures") or ["not checked"])
        )

    indeterminate = bool(blocking)
    unexpected_positive = bool(
        not indeterminate
        and canonical_clears is True
        and swap_clears is True
        and full_beats_control is True
    )
    ceiling = not indeterminate and not unexpected_positive

    # Secondary mechanistic flag only — recorded, never primary.
    disc_indep_wilson = disc.get("independent_canonical_wilson")
    disc_includes_chance = _ci_includes(disc_indep_wilson)
    disc_antisym = disc.get("antisym_accuracy")
    disc_indep = disc.get("independent_canonical_accuracy")
    disc_delta = (
        None
        if disc_antisym is None or disc_indep is None
        else round(abs(float(disc_antisym) - float(disc_indep)), 6)
    )
    degeneracy = bool(
        disc_includes_chance is True
        and disc_delta is not None
        and disc_delta >= DEGENERACY_DELTA_THRESHOLD
    )

    if indeterminate:
        primary = "indeterminate"
        decision = (
            "indeterminate: the inputs the protocol adjudicates on are missing, "
            "internally inconsistent, or do not match the pre-declared training "
            "budget, so no primary outcome is asserted. "
            f"Blocking: {'; '.join(blocking[:6])}. "
            "stop_training stays true."
        )
    elif unexpected_positive:
        primary = "unexpected_positive"
        decision = (
            "unexpected_positive: independent decisions clear chance on both "
            "renderings of the polarity-balanced slice and full-set independent "
            "beats the locked control. This is not a method win. It is the only "
            "outcome the protocol allows a limited follow-up for. stop further "
            "training until review."
        )
    else:
        primary = "ceiling_holds"
        decision = (
            "ceiling_holds: the run did not meet the adjudication criterion for "
            "a usable independent decision, and its full-set independent point "
            "estimate did not approach the locked 0.8502 reference. This is an "
            "adjudication label, not proof that all relational information is "
            "absent. stop_training stays true."
        )

    return {
        "headline_cell": "prose/balanced/ALL",
        "primary_outcome": primary,
        "outcome_states": {
            "indeterminate": indeterminate,
            "unexpected_positive": unexpected_positive,
            "ceiling_holds": ceiling,
        },
        "pre_registered_rule": (
            "Failure if balanced independent stays at chance OR the full-set "
            "independent point estimate does not exceed the locked 0.8502 "
            "reference (0.8433 published prose). Unexpected positive requires "
            "escaping both arms."
        ),
        "adjudication_estimand": {
            "amendment": f"{AMENDMENT_ID} ({AMENDMENT_DATE}), post-run",
            "status": (
                "post-run adjudication amendment — NOT part of the exact "
                "pre-registered numerical rule"
            ),
            "criterion": (
                "usable independent decision: balanced canonical accuracy and "
                "balanced swap accuracy must each exceed 0.5 with a Wilson 95% "
                "lower bound above 0.5, and the full-set independent point "
                "estimate must exceed the locked 0.8502 reference"
            ),
            "why": (
                "The pre-registered phrase 'both-directions-correct also leaves "
                "chance' fixed no numeric null. Gating on joint both-correct "
                "against a fixed constant is not the intended estimand: the "
                "uncoupled baseline is p_canonical * p_swap, which equals 0.25 "
                "only when both marginals are exactly 0.5. Requiring each "
                "rendering's decision to clear chance is the directly "
                "interpretable reading of 'usable independent decision'."
            ),
        },
        "reference_levels": {
            "independent_canonical_chance": CHANCE,
            "independent_swap_chance": CHANCE,
            "both_correct_random_baseline": BOTH_CORRECT_RANDOM_BASELINE,
            "both_correct_random_baseline_note": (
                "0.25 is the accuracy of two independent fair-coin decisions "
                "both landing correct. It is an absolute random baseline only — "
                "not a universal null, not the null for this system, and not "
                "evidence of positive coupling. The uncoupled baseline is "
                "p_canonical * p_swap; the attainable ceiling is "
                "1 - frozen_fraction. It is reported for orientation and is "
                "not the adjudication gate."
            ),
            "both_correct_cap_identity": (
                "both_correct <= 1 - frozen_fraction. A frozen pair answers the "
                "same side to both renderings while gold is mirrored, so exactly "
                "one is correct and both_correct is 0 for it."
            ),
            "both_correct_exact_identity": (
                "both_correct = (canonical_accuracy + swap_accuracy - "
                "frozen_fraction) / 2"
            ),
        },
        "balanced_canonical_clears_chance": canonical_clears,
        "balanced_swap_clears_chance": swap_clears,
        "full_independent_point_exceeds_v4_reference": full_beats_control,
        "full_control_comparison_note": (
            "Point-estimate comparison against the locked 0.8502 char-net "
            "reference. This is a conservative follow-up gate, NOT a paired "
            "superiority test — no significance is claimed either way."
        ),
        "balanced_identity_check": identity,
        "balanced_coupling_diagnostic": _coupling_diagnostic(balanced),
        "balanced_unfrozen_diagnostic": balanced.get("both_correct_given_unfrozen"),
        "provenance_ok": provenance_ok,
        "prediction_provenance_ok": prediction_provenance_ok,
        "blocking": blocking,
        "degeneracy_reappears": degeneracy,
        "degeneracy_is_secondary": True,
        "degeneracy_delta_threshold": DEGENERACY_DELTA_THRESHOLD,
        "degeneracy_observed_delta": disc_delta,
        "degeneracy_note": (
            "Secondary descriptive operationalization: fires when "
            "|antisym_accuracy - independent_canonical_accuracy| on the full "
            f"discordant cell is >= {DEGENERACY_DELTA_THRESHOLD} while that "
            "cell's independent Wilson interval still includes 0.5. The "
            f"{DEGENERACY_DELTA_THRESHOLD} threshold is descriptive and is NOT "
            "part of the primary pre-registered success/failure adjudication. "
            "It is recorded alongside the primary outcome and never replaces "
            "or modifies it."
        ),
        # Retained for backwards compatibility with existing readers.
        "full_independent_beats_v4_control": full_beats_control,
        # Retained for backwards compatibility with existing readers.
        "unexpected_positive": unexpected_positive,
        "ceiling_holds": ceiling,
        "stop_training": True,
        "decision": decision,
        "claim_boundaries": [
            "one seed, one backbone",
            "not a method win",
            "not a continuation of the locked 2/3/4/6/8-epoch curve",
            "no transfer claim",
            "no further training authorised",
            "ceiling_holds is an adjudication label, not proof that all "
            "relational information is absent",
        ],
        "locked_prose_control": LOCKED_PROSE_CONTROL,
        "v4_full_char_net_control": V4_FULL_CONTROL,
    }


def _coupling_diagnostic(block: Mapping[str, Any]) -> dict[str, Any]:
    """Secondary: observed both-correct against the marginal-conditioned baseline."""

    canonical = block.get("independent_canonical_accuracy")
    swap = block.get("independent_swap_accuracy")
    observed = block.get("independent_both_correct")
    baseline = marginal_both_correct_baseline(canonical, swap)
    frozen = block.get("frozen_fraction")
    return {
        "status": "secondary diagnostic — descriptive, not a test",
        "observed_both_correct": observed,
        "uncoupled_baseline_p_canonical_times_p_swap": (
            None if baseline is None else round(baseline, 6)
        ),
        "excess_over_uncoupled_baseline": (
            None
            if baseline is None or observed is None
            else round(float(observed) - baseline, 6)
        ),
        "attainable_cap_1_minus_frozen": (
            None if frozen is None else round(both_correct_cap(frozen), 6)
        ),
        "note": (
            "No inference is drawn from this comparison. Turning it into a "
            "claim requires a pre-specified paired bootstrap or permutation "
            "over pairs, which this analysis does not perform."
        ),
    }


# --------------------------------------------------------------------------
# Exact per-slice counts and intervals
# --------------------------------------------------------------------------


def unfrozen_diagnostic(
    n_unfrozen: int, n_both_correct_unfrozen: int, n_pairs: int
) -> dict[str, Any]:
    """Post-hoc both-correct rate among pairs the model did not freeze.

    Computed from integer counts, never by dividing rounded aggregate rates.
    Reported with its coverage so the conditioning is visible.
    """

    if n_unfrozen <= 0:
        return {
            "status": "post-hoc, descriptive — not part of the pre-registered verdict",
            "n_unfrozen": 0,
            "point": None,
            "wilson": None,
            "unfrozen_coverage": 0.0 if n_pairs else None,
        }
    return {
        "status": "post-hoc, descriptive — not part of the pre-registered verdict",
        "n_unfrozen": int(n_unfrozen),
        "n_both_correct_unfrozen": int(n_both_correct_unfrozen),
        "point": round(n_both_correct_unfrozen / n_unfrozen, 4),
        "wilson": wilson_interval(int(n_both_correct_unfrozen), int(n_unfrozen)),
        "unfrozen_coverage": (
            None if not n_pairs else round(n_unfrozen / n_pairs, 4)
        ),
        "note": (
            "Conditioning on 'not frozen' is chosen after seeing the frozen "
            "share. On unfrozen pairs canonical_correct == swap_correct holds "
            "identically, so this equals independent canonical accuracy there."
        ),
    }


def attach_wilsons(
    system: dict[str, Any],
    rows: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Add exact counts and the Wilson intervals the frozen analyser omits."""

    def _in_slice(pair: Mapping[str, Any], slice_name: str, cell: str) -> bool:
        if slice_name == "balanced" and not pair["balanced"]:
            return False
        if cell == "ALL":
            return True
        return pair["cell"] == cell

    for family in ("glyph", "prose"):
        pairs = build_pairs(rows, family)
        resolved, _ = resolve_pairs(pairs, predictions)
        slices = (system.get("families") or {}).get(family, {}).get("slices") or {}
        for slice_name, cell in (
            ("balanced", "ALL"),
            ("balanced", "concordant"),
            ("balanced", "discordant"),
            ("full", "ALL"),
            ("full", "concordant"),
            ("full", "discordant"),
        ):
            key = f"{slice_name}/{cell}"
            block = slices.get(key)
            if not isinstance(block, dict):
                continue
            selected = [
                outcome
                for pair, outcome in resolved
                if _in_slice(pair, slice_name, cell)
            ]
            block["independent_canonical_wilson"] = _wilson_flags(
                [bool(o["canonical_correct"]) for o in selected]
            )
            block["independent_swap_wilson"] = _wilson_flags(
                [bool(o["swap_correct"]) for o in selected]
            )
            block["independent_both_correct_wilson"] = _wilson_flags(
                [bool(o["both_correct"]) for o in selected]
            )
            block["antisym_wilson"] = _wilson_flags(
                [bool(o["antisym_correct"]) for o in selected]
            )

            n_pairs = len(selected)
            unfrozen = [o for o in selected if not o["frozen"]]
            counts = {
                "n_pairs": n_pairs,
                "n_frozen": sum(1 for o in selected if o["frozen"]),
                "n_unfrozen": len(unfrozen),
                "n_canonical_correct": sum(1 for o in selected if o["canonical_correct"]),
                "n_swap_correct": sum(1 for o in selected if o["swap_correct"]),
                "n_both_correct": sum(1 for o in selected if o["both_correct"]),
                "n_both_correct_unfrozen": sum(1 for o in unfrozen if o["both_correct"]),
            }
            block["exact_counts"] = counts
            block["both_correct_given_unfrozen"] = unfrozen_diagnostic(
                counts["n_unfrozen"], counts["n_both_correct_unfrozen"], n_pairs
            )
    return system
