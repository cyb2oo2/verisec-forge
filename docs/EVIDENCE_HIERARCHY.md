# Evidence Hierarchy

Not every result in this repository carries the same evidential weight. A
skeptical reader should be able to see, per claim, *what kind* of evidence backs
it and how much to trust it. This document defines the tiers, places the main
claims in them, fixes the relational-metric reporting contract, and flags which
evidence is still pending human confirmation.

## Tiers (strongest to weakest)

**T1 — Controlled behavioral intervention.** A single factor is varied while
everything else is held byte-fixed, with a preregistered expected relation and a
cross-check that isolates the factor. Model predictions are deterministic
(no AI classifier in the loop). Example: the label-only vs polarity-only 2×2
(`reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`), where the
`polarity_only_swap` ≈ `side_swap` cross-check (`phi=+0.892`) pins the effect to
polarity alone.

**T2 — Controlled comparison with a marginal-conditioned baseline.** A metric is
compared against the floor an independent, marginal-matched predictor would
reach (see the metric contract below). Example: side-swap equivariance vs its
independence baseline; the positional-independence result
(`reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`).

**T3 — Observational / correlational, single checkpoint.** A measured
association without a clean isolating intervention, or a single-checkpoint
result whose generality is untested. Most mechanism-arc numbers are T3 *for
generality* even when T1 for isolation: one checkpoint, one length, 600 pairs.

**T4 — Structural control, not a reasoning claim.** A post-hoc mechanism that
changes a number without evidence the model reasons better. Example: the
relation-consistent decoder (`0.3042 → 0.0000` violation rate) — explicitly a
projection, never cited as repaired reasoning
(`reports/DECODER_STRESS_VALIDATION.md`).

**T5 — AI-classified, human confirmation pending.** A label or judgment produced
by an automated classifier that has not yet been human-adjudicated. Usable for
piloting and direction-setting; **not** load-bearing for a headline claim until
promoted.

## Claim placement

| Claim | Tier | Report |
| --- | --- | --- |
| Polarity, not labels, drives the side-swap failure | T1 (isolation) / T3 (generality) | `QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` |
| Polarity is a nuisance var; augmentation already applied, didn't fix it | T1 | `POLARITY_GOLD_CONFOUND.md` |
| Side-swap predictions ≈ independent of canonical | T2 | `QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md` |
| Endpoint fix does not transfer to side-order | T2 | `QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md` |
| Relational failure appears in Qwen and CodeBERT | T2 / T3 | `CROSS_MODEL_RELATIONAL_AUDIT.md` |
| Pair-coupled decoding is the strongest system layer | T2 | `PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md` |
| Relation-consistent decoding removes violations | T4 | `DECODER_STRESS_VALIDATION.md` |
| Evidence localization tracks side-correctness | T3 / **T5** | `PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`, round-3 pilot |

## Relational-metric reporting contract

`relation_violation_rate` (`src/vrf/relational_evaluation.py`,
`= 1 − mean(relation_success)`) is the canonical relational metric. To be
citable it must be reported with **all three** of:

1. **Raw, single-pass predictions.** No test-time symmetrization, averaging over
   renderings, or decoder projection. Those belong in a separate row labeled as
   such; the headline number is the raw model.
2. **Pair-cluster bootstrap CI** (`pair_cluster_bootstrap`), resampling by
   `dataset::pair_key` so the interval respects pair structure.
3. **Marginal-conditioned baseline**
   (`marginal_conditioned_violation_baseline`) — the violation rate an
   independent predictor with the *same* base/transformed A-rates would produce.
   A model sitting at this baseline is statistically two independent
   classifiers; the reported gap `baseline − observed` is the real relational
   signal. For balanced marginals the invariant baseline is ~0.5 and the
   equivariant baseline is also ~0.5, so an observed violation rate near 0.5 is
   the *floor*, not a mild failure.

A relational improvement is only credible when the raw single-pass violation
rate drops **below its marginal-conditioned baseline** with a bootstrap CI that
excludes the baseline.

## Human-confirmation status

The mechanism arc (endpoint, positional independence, label-only, polarity-only)
runs on **deterministic model predictions from the joint-pairwise checkpoint**;
no AI classifier sits in that loop, so those results are not T5.

The **evidence-localization / manual-evidence line** is different. Round 2 was
human-adjudicated; **round 3 is AI-pilot-classified with human confirmation
deferred** (PR #45). Any claim that leans on round-3 localization labels is T5
until human adjudication lands and must be marked as such in its report. Do not
promote a T5 result into a headline table.
