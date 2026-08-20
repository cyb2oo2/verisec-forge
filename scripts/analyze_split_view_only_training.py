"""Evaluate the Arc 2 Q1 split-view-only checkpoint.

Reads committed v4 suite rows and one prediction file. No extra training.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.artifact_guard import require_artifact
from vrf.frozen_pairs_decomposition import analyse_system, strongest_controls
from vrf.io_utils import read_json, read_jsonl, write_json
from vrf.relational_report_contract import (
    exact_mirror_rejection_table,
    load_admissible_suite_summary,
    require_relational_report_contract,
)
from vrf.reproducibility import (
    capture_artifact_provenance,
    normalized_provenance_bytes,
    sha256_file,
)
from vrf.split_view_only import (
    AMENDMENT_DATE,
    AMENDMENT_ID,
    BOTH_CORRECT_RANDOM_BASELINE,
    DEGENERACY_DELTA_THRESHOLD,
    LOCKED_PROSE_CONTROL,
    PREDECLARED_EPOCHS,
    PREDECLARED_STEPS,
    V4_FULL_CONTROL,
    apply_pre_registered_verdict,
    attach_wilsons,
    normalize_checkpoint_id,
    validate_prediction_artifact,
    validate_provenance,
)

DEFAULT_SUITE = "data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl"
DEFAULT_SUMMARY = "reports/secure_code_relational_benchmark_v4_summary.json"
DEFAULT_PREDICTIONS = (
    "outputs/secure_code_v4_split_view_only_qwen3b_predictions_1024.jsonl"
)
DEFAULT_STATUS = "reports/repair_train_status_split_view_only_qwen3b_v1.json"
DEFAULT_OUTPUT = "reports/veripatch_rr_split_view_only_training.json"
DEFAULT_MARKDOWN = "reports/SPLIT_VIEW_ONLY_TRAINING_V1.md"
DEFAULT_REFERENCE = (
    "outputs/secure_code_v4_polarity_balanced_scaled_4ep_predictions_1024.jsonl"
)


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _wilson_cell(interval: dict[str, Any] | None) -> str:
    if not interval or interval.get("point") is None:
        return "—"
    return (
        f"`{_fmt(interval['point'])}` "
        f"[`{_fmt(interval['low'])}`, `{_fmt(interval['high'])}`]"
    )


def _slice(system: dict[str, Any], family: str, name: str) -> dict[str, Any]:
    return system["families"][family]["slices"][name]


def render_markdown(payload: dict[str, Any]) -> str:
    verdict = payload["verdict"]
    control = payload["families"]["prose"]["strongest_control"]
    rejection = payload["exact_mirror_rejection"]
    trained = payload["systems"]["split_view_only"]
    provenance = payload["provenance_check"]
    prediction = payload["prediction_provenance_check"]
    repro = payload.get("reproducibility") or {}
    lines = [
        "# Split-View-Only Training (Arc 2 Q1)",
        "",
        f"Artifact: `{payload['artifact']}`",
        f"Script: `scripts/analyze_split_view_only_training.py`",
        f"Protocol: `docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md`",
        f"Config: `{payload['config']}`",
        f"Suite: `{payload['suite']}` (admissible `{payload['suite_version']}`)",
        f"Checkpoint: `{payload['checkpoint']}`",
        "",
        "**This does not revive the locked antisymmetric epoch-curve claims.** "
        "It is one from-scratch 3B run on `split_view` only. "
        "`stop_training = true` for the old glyph-exposed curve is unchanged.",
        "",
        "## Pre-registered protocol (written before the run)",
        "",
        f"- Budget: `{PREDECLARED_EPOCHS}` epochs, `{PREDECLARED_STEPS}` "
        "optimizer steps, seed 7, 2,208 polarity-balanced pairs.",
        "- Init: base `Qwen/Qwen2.5-Coder-3B-Instruct` + fresh LoRA. No "
        "polarity-balanced, prose-native, or joint-pairwise checkpoint.",
        "- Rendering: `split_view` only. Glyph layout forbidden in the trainer.",
        "- Primary cell: prose / polarity-balanced / ALL (n=308).",
        f"- Published prose-control comparator: `{LOCKED_PROSE_CONTROL}` "
        f"(Arc 2). v4 char-net on this suite: `{V4_FULL_CONTROL}` full, "
        "`0.5000` balanced.",
        "- Failure: balanced independent Wilson includes `0.5`, **or** "
        "full-set independent does not exceed the v4 control.",
        "- Unexpected positive: both failure arms escaped. Not a method win.",
        "- Do not add epochs, seeds, or mined pairs.",
        "",
        f"### Adjudication criterion — Amendment {AMENDMENT_ID} "
        f"({AMENDMENT_DATE}, **post-run**)",
        "",
        "The pre-registered phrase *\"both-directions-correct also leaves "
        "chance\"* fixed no numeric null. The operationalization below was "
        "written **after** the run and is **not** part of the exact "
        "pre-registered numerical rule. It does not change this run's "
        "outcome. See `docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md`, "
        f"Amendment {AMENDMENT_ID}.",
        "",
        "Unexpected positive requires **all** of:",
        "",
        "| Requirement | Level | Uncertainty |",
        "| --- | --- | --- |",
        "| Balanced canonical accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |",
        "| Balanced swap accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |",
        f"| Full-set independent accuracy | `> {V4_FULL_CONTROL}` | locked control |",
        "",
        "Gating on joint both-correct against a fixed constant is *not* the "
        "estimand: the uncoupled baseline is `p_canonical * p_swap`, which "
        f"equals `{BOTH_CORRECT_RANDOM_BASELINE}` only when both marginals are "
        "exactly `0.5`. Canonical `0.80` with swap `0.40` and both-correct "
        "`0.32` would clear a fixed `0.25` while the swap decision sits *below* "
        "chance with no coupling beyond the marginals.",
        "",
        "## Train status and provenance",
        "",
        "Validated against the pre-declared budget before any verdict is "
        f"issued. A missing or mismatched field forces `indeterminate`. "
        f"All checks pass: `{provenance['ok']}`.",
        "",
        "| Field | Observed | Expected | ok |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, check in provenance["checks"].items():
        lines.append(
            f"| `{name}` | `{check['observed']}` | `{check['expected']}` | "
            f"`{check['ok']}` |"
        )
    if provenance["failures"]:
        lines.extend(["", "Failures:", ""])
        lines.extend(f"- `{failure}`" for failure in provenance["failures"])

    lines.extend(
        [
            "",
            "### Prediction artifact binding",
            "",
            "The evaluated predictions are bound to the validated run before "
            f"any verdict is issued. All checks pass: `{prediction['ok']}`.",
            "",
            f"- prediction rows: `{prediction['n_prediction_rows']}`, unique ids: "
            f"`{prediction['n_unique_prediction_ids']}`",
            f"- model_id(s): `{prediction['model_ids']}`",
            f"- normalized model_id: `{prediction['normalized_model_id']}` — "
            f"checkpoint: `{prediction['normalized_checkpoint']}` — expected "
            f"output dir: `{prediction['expected_output_dir']}`",
            f"- required suite renderings: `{prediction['n_required_renderings']}`, "
            f"absent: `{prediction['n_required_renderings_absent']}`, malformed "
            f"probabilities: `{prediction['n_malformed_probabilities']}`",
            "",
            "| Family | expected full | resolved full | expected balanced | resolved balanced | pairs missing predictions |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for family, cov in prediction["coverage"].items():
        lines.append(
            f"| {family} | {cov['expected_full_pairs']} | "
            f"{cov['resolved_full_pairs']} | {cov['expected_balanced_pairs']} | "
            f"{cov['resolved_balanced_pairs']} | "
            f"{cov['pairs_missing_predictions']} |"
        )
    lines.append("")
    lines.append(
        "Expected counts are derived from the loaded admissible suite, not "
        "hard-coded."
    )
    if prediction["failures"]:
        lines.extend(["", "Failures:", ""])
        lines.extend(f"- `{failure}`" for failure in prediction["failures"])

    repro_artifacts = repro.get("artifacts") or {}
    lines.extend(
        [
            "",
            "### Reproducibility binding",
            "",
            f"- git commit: `{repro.get('git_commit')}`",
            f"- working tree dirty: `{repro.get('git_working_tree_dirty')}` "
            f"(`{repro.get('provenance_quality')}`)",
            f"- checkpoint identity: "
            f"`{(repro.get('checkpoint_identity') or {}).get('checkpoint')}` "
            f"(model `{(repro.get('checkpoint_identity') or {}).get('model_name')}`); "
            "checkpoint weights are local and deliberately not hashed",
            f"- **publication_ready: `{repro.get('publication_ready')}`**",
            "",
            "| Role | Path | SHA256 (LF-normalized) | bytes | tracked | gitignored |",
            "| --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    for role, entry in repro_artifacts.items():
        if entry.get("status") == "missing":
            lines.append(f"| {role} | `{entry['path']}` | — | — | — | — |")
            continue
        lines.append(
            f"| {role} | `{entry['path']}` | `{entry['sha256'][:16]}…` | "
            f"{entry['bytes']} | `{entry['git_tracked']}` | "
            f"`{entry['git_ignored']}` |"
        )
    if repro.get("gitignored_inputs") or repro.get("missing_inputs"):
        lines.extend(
            [
                "",
                "**Publication readiness is `false`.** Gitignored inputs: "
                f"`{repro.get('gitignored_inputs')}`; missing inputs: "
                f"`{repro.get('missing_inputs')}`. The manifest binds these by "
                "content hash, but they are not in committed history, so their "
                "provenance cannot be reconstructed from the repository alone. "
                "This is reported rather than papered over.",
            ]
        )

    lines.extend(
        [
            "",
        "## Verdict",
        "",
        verdict["decision"],
        "",
        f"**Primary outcome: `{verdict['primary_outcome']}`.** The three states "
        "are adjudicated explicitly and are mutually exclusive.",
        "",
        "| State | Value |",
        "| --- | ---: |",
        f"| indeterminate | `{verdict['outcome_states']['indeterminate']}` |",
        f"| unexpected_positive | `{verdict['outcome_states']['unexpected_positive']}` |",
        f"| ceiling_holds | `{verdict['outcome_states']['ceiling_holds']}` |",
        "",
        "Adjudicated inputs:",
        "",
        f"- balanced canonical clears `0.5` from above: "
        f"`{verdict['balanced_canonical_clears_chance']}`",
        f"- balanced swap clears `0.5` from above: "
        f"`{verdict['balanced_swap_clears_chance']}`",
        f"- full-set independent **point estimate** exceeds the locked "
        f"`{V4_FULL_CONTROL}` reference: "
        f"`{verdict['full_independent_point_exceeds_v4_reference']}` "
        "(point-estimate gate, not a paired superiority test)",
        f"- provenance matches the pre-declared budget: "
        f"`{verdict['provenance_ok']}`",
        f"- prediction artifact is bound to the validated run: "
        f"`{verdict['prediction_provenance_ok']}`",
        f"- balanced slice satisfies "
        f"`both_correct = (canonical + swap - frozen)/2`: "
        f"`{verdict['balanced_identity_check'].get('consistent')}` "
        f"(residual `{verdict['balanced_identity_check'].get('residual')}`)",
        f"- stop_training: `{verdict['stop_training']}`",
        "",
        f"Secondary mechanistic flag — degeneracy_reappears: "
        f"`{verdict['degeneracy_reappears']}` (threshold "
        f"`|antisym - independent| >= {verdict['degeneracy_delta_threshold']}` "
        f"on prose/full/discordant; observed delta "
        f"`{_fmt(verdict['degeneracy_observed_delta'])}`). "
        f"{verdict['degeneracy_note']}",
        "",
        "## Strongest semantics-free control",
        "",
        f"Rule: `{control['name']}` — {control['description']}.",
        "",
        "| Slice | n | control accuracy |",
        "| --- | ---: | ---: |",
        f"| full (nonzero-net) | {control['full']['n_pairs']} | `{_fmt(control['full']['control_accuracy'])}` |",
        f"| polarity-balanced | {control['balanced']['n_pairs']} | `{_fmt(control['balanced']['control_accuracy'])}` |",
        "",
        control["note"],
        "",
        f"Locked Arc 2 prose control on the 600-pair `split_view` measurement: "
        f"`{LOCKED_PROSE_CONTROL}`. That number is not recomputed here.",
        "",
        "## Exact-mirror rejection (suite construction)",
        "",
        f"Invariant: {rejection['invariant']}.",
        "",
        "| Source | pairs seen | rejected non-mirror | rate | sampled |",
        "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, row in rejection["sources"].items():
        rate = row["non_mirror_rejection_rate"]
        rate_s = f"{rate:.4f}" if isinstance(rate, float) else str(rate)
        lines.append(
            f"| {name} | {row.get('pairs_seen', '—')} | "
            f"{row['rejected_non_mirror_pairs']} | `{rate_s}` | "
            f"{row.get('sampled_pairs', '—')} |"
        )

    bal = _slice(trained, "prose", "balanced/ALL")
    bal_disc = _slice(trained, "prose", "balanced/discordant")
    full = _slice(trained, "prose", "full/ALL")
    disc = _slice(trained, "prose", "full/discordant")
    conc = _slice(trained, "prose", "full/concordant")
    glyph_full = _slice(trained, "glyph", "full/ALL")
    glyph_disc = _slice(trained, "glyph", "full/discordant")
    glyph_bal = _slice(trained, "glyph", "balanced/ALL")

    lines.extend(
        [
            "",
            "## Primary — prose / polarity-balanced (train-matched split_view)",
            "",
            "Char-net and the prose header rule are `0.50` on this slice. "
            "Independent is the 0.5-threshold per-rendering decision. "
            "Antisym is the pair-level projection, reported only as the "
            "secondary degeneracy check.",
            "",
            "Chance is `0.50` for both per-rendering decisions. The "
            "adjudication gate is canonical **and** swap, each clearing `0.50` "
            "from above. Both-correct is a diagnostic column, not a gate: "
            f"`{BOTH_CORRECT_RANDOM_BASELINE}` is the absolute baseline for two "
            "independent 50/50 random decisions and nothing more — the "
            "uncoupled baseline is `p_canonical * p_swap`, and "
            "`both_correct <= 1 - frozen` caps the column outright.",
            "",
            "| Cell | n | indep canonical (Wilson) | indep swap (Wilson) | both-correct (Wilson) | antisym | frozen | control |",
            "| --- | ---: | --- | --- | --- | ---: | ---: | ---: |",
            (
                f"| ALL | {bal['n_pairs']} | "
                f"{_wilson_cell(bal.get('independent_canonical_wilson'))} | "
                f"{_wilson_cell(bal.get('independent_swap_wilson'))} | "
                f"{_wilson_cell(bal.get('independent_both_correct_wilson'))} | "
                f"`{_fmt(bal.get('antisym_accuracy'))}` | "
                f"`{_fmt(bal.get('frozen_fraction'))}` | "
                f"`{_fmt(bal.get('control_accuracy'))}` |"
            ),
            (
                f"| discordant | {bal_disc['n_pairs']} | "
                f"{_wilson_cell(bal_disc.get('independent_canonical_wilson'))} | "
                f"{_wilson_cell(bal_disc.get('independent_swap_wilson'))} | "
                f"{_wilson_cell(bal_disc.get('independent_both_correct_wilson'))} | "
                f"`{_fmt(bal_disc.get('antisym_accuracy'))}` | "
                f"`{_fmt(bal_disc.get('frozen_fraction'))}` | "
                f"`{_fmt(bal_disc.get('control_accuracy'))}` |"
            ),
            "",
            "### Exact counts (balanced / ALL)",
            "",
            "| Quantity | Count |",
            "| --- | ---: |",
        ]
    )
    counts = bal.get("exact_counts") or {}
    for label, key in (
        ("pairs", "n_pairs"),
        ("frozen", "n_frozen"),
        ("unfrozen", "n_unfrozen"),
        ("canonical correct", "n_canonical_correct"),
        ("swap correct", "n_swap_correct"),
        ("both correct", "n_both_correct"),
        ("both correct, unfrozen", "n_both_correct_unfrozen"),
    ):
        lines.append(f"| {label} | {counts.get(key, '—')} |")

    unfrozen = bal.get("both_correct_given_unfrozen") or {}
    coupling = verdict.get("balanced_coupling_diagnostic") or {}
    lines.extend(
        [
            "",
            "### Secondary diagnostics (post-hoc, descriptive)",
            "",
            "Neither feeds the verdict.",
            "",
            "**Both-correct among unfrozen pairs** — computed from the integer "
            "counts above, not from rounded rates: "
            f"`{unfrozen.get('n_both_correct_unfrozen')}`/"
            f"`{unfrozen.get('n_unfrozen')}` = `{_fmt(unfrozen.get('point'))}`, "
            f"Wilson 95% {_wilson_cell(unfrozen.get('wilson'))}, covering "
            f"`{_fmt(unfrozen.get('unfrozen_coverage'))}` of the slice. "
            "Conditioning on 'not frozen' was chosen after seeing the frozen "
            "share, so this is descriptive only. On unfrozen pairs "
            "`canonical_correct == swap_correct` holds identically, so it "
            "equals independent canonical accuracy there.",
            "",
            "**Coupling** — observed both-correct "
            f"`{_fmt(coupling.get('observed_both_correct'))}` against the "
            "marginal-conditioned baseline `p_canonical * p_swap` = "
            f"`{_fmt(coupling.get('uncoupled_baseline_p_canonical_times_p_swap'))}` "
            f"(excess `{_fmt(coupling.get('excess_over_uncoupled_baseline'))}`, "
            "attainable cap `1 - frozen` = "
            f"`{_fmt(coupling.get('attainable_cap_1_minus_frozen'))}`). "
            "No inference is drawn: a claim here would need a pre-specified "
            "paired bootstrap or permutation over pairs, which this analysis "
            "does not perform.",
            "",
            "## Prose / full set (train-matched split_view)",
            "",
            "| Cell | n | indep canonical (Wilson) | antisym (Wilson) | frozen | control |",
            "| --- | ---: | --- | --- | ---: | ---: |",
            (
                f"| ALL | {full['n_pairs']} | "
                f"{_wilson_cell(full.get('independent_canonical_wilson'))} | "
                f"{_wilson_cell(full.get('antisym_wilson'))} | "
                f"`{_fmt(full.get('frozen_fraction'))}` | "
                f"`{_fmt(full.get('control_accuracy'))}` |"
            ),
            (
                f"| concordant | {conc['n_pairs']} | "
                f"{_wilson_cell(conc.get('independent_canonical_wilson'))} | "
                f"{_wilson_cell(conc.get('antisym_wilson'))} | "
                f"`{_fmt(conc.get('frozen_fraction'))}` | "
                f"`{_fmt(conc.get('control_accuracy'))}` |"
            ),
            (
                f"| discordant | {disc['n_pairs']} | "
                f"{_wilson_cell(disc.get('independent_canonical_wilson'))} | "
                f"{_wilson_cell(disc.get('antisym_wilson'))} | "
                f"`{_fmt(disc.get('frozen_fraction'))}` | "
                f"`{_fmt(disc.get('control_accuracy'))}` |"
            ),
            "",
            "## Glyph family (reference only — never trained on)",
            "",
            "| Cell | n | indep canonical | antisym | frozen | control |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            (
                f"| balanced ALL | {glyph_bal['n_pairs']} | "
                f"`{_fmt(glyph_bal.get('independent_canonical_accuracy'))}` | "
                f"`{_fmt(glyph_bal.get('antisym_accuracy'))}` | "
                f"`{_fmt(glyph_bal.get('frozen_fraction'))}` | "
                f"`{_fmt(glyph_bal.get('control_accuracy'))}` |"
            ),
            (
                f"| full ALL | {glyph_full['n_pairs']} | "
                f"`{_fmt(glyph_full.get('independent_canonical_accuracy'))}` | "
                f"`{_fmt(glyph_full.get('antisym_accuracy'))}` | "
                f"`{_fmt(glyph_full.get('frozen_fraction'))}` | "
                f"`{_fmt(glyph_full.get('control_accuracy'))}` |"
            ),
            (
                f"| full discordant | {glyph_disc['n_pairs']} | "
                f"`{_fmt(glyph_disc.get('independent_canonical_accuracy'))}` | "
                f"`{_fmt(glyph_disc.get('antisym_accuracy'))}` | "
                f"`{_fmt(glyph_disc.get('frozen_fraction'))}` | "
                f"`{_fmt(glyph_disc.get('control_accuracy'))}` |"
            ),
            "",
            "## Mechanistic reading",
            "",
            payload["interpretation"],
            "",
            "## What this does and does not claim",
            "",
            "- **One seed, one backbone**, the pre-declared 1,104 steps. No "
            "further training was run and none is authorised.",
            "- Not a method win for pair-coupled decoding or a new training recipe.",
            "- Not a continuation of the locked 2/3/4/6/8-epoch curve.",
            "- Not a replacement for the locked `split_view` collapse "
            "(`0.5133` / `0.4850` vs prose control `0.8433`).",
            "- **No transfer claim.** CrossVul rows in the v4 *evaluation* "
            "suite were held out of this training set's construction keys; "
            "CrossVul pairs that are not those keys may still appear in the "
            "2,208-pair train pool, as in the locked polarity-balanced set.",
            "- **`ceiling_holds` is an adjudication label, not proof that all "
            "relational information is absent.** Failing to reject chance is "
            "not evidence of no signal. The run did not meet the criterion; "
            "that is the whole of what is claimed.",
            "- The unfrozen-subset diagnostic is post-hoc and descriptive. It "
            "does not reopen training.",
            "",
            "## Reproducing",
            "",
            "```",
            "python scripts/train_antisymmetric_repair.py \\",
            "  --config configs/research_split_view_only_qwen3b_v1.json",
            "python scripts/predict_veripatch_rr.py \\",
            "  --checkpoint checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1 \\",
            "  --dataset data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl \\",
            "  --output outputs/secure_code_v4_split_view_only_qwen3b_predictions_1024.jsonl \\",
            "  --batch-size 4 --resume --num-labels 2",
            "python scripts/analyze_split_view_only_training.py",
            "```",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def _interpretation(payload: dict[str, Any]) -> str:
    verdict = payload["verdict"]
    trained = payload["systems"]["split_view_only"]
    bal = _slice(trained, "prose", "balanced/ALL")
    disc = _slice(trained, "prose", "full/discordant")
    full = _slice(trained, "prose", "full/ALL")
    outcome = verdict["primary_outcome"]

    if outcome == "indeterminate":
        return (
            "No primary outcome is asserted. The inputs the protocol "
            "adjudicates on are missing, internally inconsistent, or do not "
            "match the pre-declared training budget: "
            f"{'; '.join(verdict.get('blocking') or [])}. Nothing here should "
            "be quoted as a result."
        )

    if outcome == "unexpected_positive":
        return (
            "Independent decisions cleared chance on **both** renderings of the "
            "polarity-balanced `split_view` slice (canonical "
            f"`{_fmt(bal.get('independent_canonical_accuracy'))}`, swap "
            f"`{_fmt(bal.get('independent_swap_accuracy'))}`) and full-set "
            f"independent `{_fmt(full.get('independent_canonical_accuracy'))}` "
            f"exceeded the locked `{V4_FULL_CONTROL}` reference as a point "
            "estimate. That is the unexpected-positive branch. It does not "
            "reopen the old epoch curve and it is not a method claim. Stop and "
            "review before any follow-up."
        )

    secondary = ""
    if verdict.get("degeneracy_reappears"):
        secondary = (
            " Secondary mechanistic flag (descriptive, threshold "
            f"`{DEGENERACY_DELTA_THRESHOLD}`, observed delta "
            f"`{_fmt(verdict.get('degeneracy_observed_delta'))}`): on the full "
            f"discordant cell the projection sits at "
            f"`{_fmt(disc.get('antisym_accuracy'))}` against independent "
            f"`{_fmt(disc.get('independent_canonical_accuracy'))}` with frozen "
            f"share `{_fmt(disc.get('frozen_fraction'))}` — the "
            "projection-versus-decision split seen on the locked glyph-exposed "
            "curve, here without any glyph exposure. This describes a "
            "mechanism; it does not change the primary outcome."
        )

    return (
        "The run did not meet the adjudication criterion for a usable "
        "independent decision, and its full-set independent point estimate did "
        "not approach the locked reference. On the train-matched prose "
        "rendering the balanced slice gives canonical "
        f"`{_fmt(bal.get('independent_canonical_accuracy'))}` and swap "
        f"`{_fmt(bal.get('independent_swap_accuracy'))}`, neither clearing "
        "`0.5` from above, and full-set independent "
        f"`{_fmt(full.get('independent_canonical_accuracy'))}` is far below "
        f"the v4 char-net reference `{V4_FULL_CONTROL}` and the locked prose "
        f"reference `{LOCKED_PROSE_CONTROL}` — a point-estimate comparison, "
        "not a paired superiority test. Starting from a fresh LoRA with no "
        "glyph exposure therefore did not yield a single-pass decision this "
        "protocol would accept. That is an adjudication outcome, not proof "
        "that the model holds no relational information — failing to reject "
        "chance is not evidence of absence, and the post-hoc unfrozen-subset "
        "diagnostic is descriptive and does not reopen training." + secondary
    )


def _reproducibility_block(
    inputs: dict[str, str], *, checkpoint: str, model_name: str | None
) -> dict[str, Any]:
    """Bind the report to its small input artifacts and checkpoint identity.

    Reuses ``vrf.reproducibility`` for git state and path-safe, LF-normalized
    SHA256 rather than adding a parallel hashing path. Checkpoint *contents*
    are never hashed — only the declared identity is recorded.
    """

    present: dict[str, str] = {}
    absent: list[str] = []
    for role, rel in inputs.items():
        path = ROOT / rel
        if path.is_file():
            present[role] = rel
        else:
            absent.append(role)

    try:
        provenance = capture_artifact_provenance(
            ROOT,
            source_paths=[present[r] for r in ("suite", "predictions") if r in present],
            config_paths=[
                present[r]
                for r in ("config", "train_status", "suite_summary")
                if r in present
            ],
            code_paths=[
                "src/vrf/split_view_only.py",
                "scripts/analyze_split_view_only_training.py",
            ],
        )
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - defensive
        provenance = {"error": str(exc)}

    artifacts: dict[str, Any] = {}
    for role, rel in present.items():
        path = ROOT / rel
        content, normalization = normalized_provenance_bytes(path)
        artifacts[role] = {
            "path": rel.replace("\\", "/"),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha256_raw_bytes": sha256_file(path),
            "bytes": path.stat().st_size,
            "normalization": normalization,
            "git_tracked": _git_tracked(rel),
            "git_ignored": _git_ignored(rel),
        }
    for role in absent:
        artifacts[role] = {"path": inputs[role], "status": "missing"}

    gitignored = sorted(
        role for role, entry in artifacts.items() if entry.get("git_ignored")
    )
    return {
        "git_commit": provenance.get("git_commit"),
        "git_working_tree_dirty": provenance.get("git_working_tree_dirty"),
        "provenance_quality": provenance.get("provenance_quality"),
        "python_version": provenance.get("python_version"),
        "platform": provenance.get("platform"),
        "artifacts": artifacts,
        "code": provenance.get("code"),
        "checkpoint_identity": {
            "checkpoint": normalize_checkpoint_id(checkpoint),
            "model_name": model_name,
            "note": (
                "Checkpoint identity only. Checkpoint weights are local, are "
                "not committed, and are deliberately not hashed here."
            ),
        },
        "missing_inputs": absent,
        "gitignored_inputs": gitignored,
        "publication_ready": not absent and not gitignored,
        "publication_readiness_note": (
            "false while any input artifact is missing or gitignored: the "
            "manifest can bind local content by hash but cannot bind it to "
            "committed history. See reproducibility/"
            "split_view_only_training_manifest.json."
        ),
    }


def _git(*args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True
        )
    except OSError:  # pragma: no cover - git absent
        return 1, ""
    return result.returncode, result.stdout.strip()


def _git_tracked(rel: str) -> bool:
    code, _ = _git("ls-files", "--error-unmatch", rel)
    return code == 0


def _git_ignored(rel: str) -> bool:
    code, _ = _git("check-ignore", "-q", rel)
    return code == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default=DEFAULT_SUITE)
    parser.add_argument("--suite-summary", default=DEFAULT_SUMMARY)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--status", default=DEFAULT_STATUS)
    parser.add_argument(
        "--config", default="configs/research_split_view_only_qwen3b_v1.json"
    )
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", default=DEFAULT_MARKDOWN)
    parser.add_argument("--reference-predictions", default=DEFAULT_REFERENCE)
    args = parser.parse_args()

    suite_path = require_artifact(
        args.suite,
        produced_by="scripts/build_relational_benchmark_v4.py",
        purpose="split-view-only evaluation",
    )
    summary = load_admissible_suite_summary(args.suite_summary)
    rows = read_jsonl(suite_path)
    pred_path = require_artifact(
        args.predictions,
        produced_by="scripts/predict_veripatch_rr.py on the split-view-only checkpoint",
        purpose="split-view-only predictions",
    )
    # Keep the raw row list: duplicate ids must be detected before any dict
    # construction could silently overwrite them.
    prediction_rows = read_jsonl(pred_path)
    prediction_check = validate_prediction_artifact(
        prediction_rows,
        rows,
        checkpoint=args.checkpoint,
    )
    predictions: dict[str, Any] = {}
    for row in prediction_rows:
        predictions.setdefault(str(row["id"]), row)

    trained = analyse_system(rows, predictions)
    trained = attach_wilsons(trained, rows, predictions)
    trained["predictions"] = str(args.predictions).replace("\\", "/")
    trained["model_id"] = prediction_check["normalized_model_id"] or None

    payload: dict[str, Any] = {
        "artifact": args.output.replace("\\", "/"),
        "config": str(args.config).replace("\\", "/"),
        "checkpoint": str(args.checkpoint).replace("\\", "/"),
        "suite": str(args.suite).replace("\\", "/"),
        "suite_summary": str(args.suite_summary).replace("\\", "/"),
        "suite_version": summary["benchmark_version"],
        "exact_mirror_rejection": exact_mirror_rejection_table(summary),
        "families": strongest_controls(rows),
        "systems": {"split_view_only": trained},
        "claim_boundary": {
            "not_a_continuation_of_the_locked_curve": True,
            "not_a_method_win": True,
            "stop_training": True,
            "does_not_replace_split_view_numbers": True,
            "one_seed_one_backbone": True,
            "no_transfer_claim": True,
            "no_further_training_authorised": True,
            "ceiling_holds_is_an_adjudication_label_not_proof_of_no_signal": True,
            "unfrozen_subset_diagnostic_is_post_hoc_descriptive": True,
        },
        "amendment": {
            "id": AMENDMENT_ID,
            "date": AMENDMENT_DATE,
            "status": "post-run",
            "document": "docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md",
            "changes_published_outcome": False,
            "authorises_further_training": False,
            "summary": (
                "The pre-registered phrase 'both-directions-correct also leaves "
                "chance' fixed no numeric null. It is operationalised post-run "
                "as a usable independent decision: balanced canonical AND "
                "balanced swap accuracy must each clear 0.5 with a Wilson 95% "
                "lower bound above 0.5, and full-set independent must beat the "
                "locked control. This is not part of the exact pre-registered "
                "numerical rule."
            ),
        },
    }
    status_path = ROOT / args.status
    config_path = ROOT / args.config
    status = read_json(status_path) if status_path.exists() else None
    config = read_json(config_path) if config_path.exists() else None
    if status is not None:
        payload["train_status"] = status
    if config is None:
        print(f"provenance: config not found at {args.config}", file=sys.stderr)
    if status is None:
        print(f"provenance: train status not found at {args.status}", file=sys.stderr)
    payload["provenance_check"] = validate_provenance(config, status)
    payload["prediction_provenance_check"] = prediction_check
    payload["resolved_config"] = config
    payload["reproducibility"] = _reproducibility_block(
        {
            "config": args.config,
            "train_status": args.status,
            "suite": args.suite,
            "suite_summary": args.suite_summary,
            "predictions": args.predictions,
        },
        checkpoint=args.checkpoint,
        model_name=(config or {}).get("model_name"),
    )
    if Path(args.reference_predictions).exists() or (
        ROOT / args.reference_predictions
    ).exists():
        ref = {
            str(row["id"]): row for row in read_jsonl(ROOT / args.reference_predictions)
        }
        reference = analyse_system(rows, ref)
        reference = attach_wilsons(reference, rows, ref)
        reference["predictions"] = str(args.reference_predictions).replace("\\", "/")
        payload["systems"]["locked_4ep_reference"] = reference

    payload["verdict"] = apply_pre_registered_verdict(payload)
    payload["interpretation"] = _interpretation(payload)
    require_relational_report_contract(payload)

    write_json(ROOT / args.output, payload)
    (ROOT / args.markdown).write_text(render_markdown(payload), encoding="utf-8")
    print(payload["verdict"]["decision"])
    print(f"wrote {args.output}")
    print(f"wrote {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
