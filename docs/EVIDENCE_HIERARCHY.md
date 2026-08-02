# Evidence Hierarchy

> **CORRECTED — WITHDRAWN RESULTS.**
> This document previously presented PrimeVul detector results as evidence of learned
> secure-patch reasoning. That interpretation was withdrawn after adversarial
> structural-control analysis. Under the closed-world pair constraint the fine-tuned
> detector reaches balanced accuracy `0.8596`; a **semantics-free character-level diff
> structural control** reaches `0.8588` on the same evaluation population. The difference
> is `+0.0008`, with a pair-group clustered 95% CI spanning zero (`[-0.0202, +0.0222]`)
> and a non-significant group-level sign test (19 vs 18, `p=1.0`).
> **This experiment does not establish semantic secure-patch reasoning beyond diff structure.**
> Current status: [Result Status Ledger](RESULT_STATUS_LEDGER.md).


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
| ~~Pair-coupled decoding is the strongest system layer~~ **WITHDRAWN** | — | `PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md` (matched by a semantics-free character control) |
| Relation-consistent decoding removes violations | T4 | `DECODER_STRESS_VALIDATION.md` |
| ~~Evidence localization tracks side-correctness~~ **WITHDRAWN (circular target)** | — | `PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`, round-3 pilot |
| Antisymmetric readout is a transferable structural fix for side-order inconsistency | T4 (exact by construction) / T2 (transfer confirmed on CrossVul + 5 nuisance families) | `REPAIR_ANTISYMMETRIC_RESULT_V1.md` (#54, #55) |
| Fine-tuning increment over the projection null | **not validated** — significant in-distribution (p=0.002) but fails both preregistered transfer tests (CrossVul p=0.508; 0/5 nuisance families at Bonferroni-corrected p<0.01, 2/5 sign-reversed) | `REPAIR_ANTISYMMETRIC_RESULT_V1.md` (#54, #55) |

## Repair evidence (#54, #55)

The antisymmetric-head repair line splits into two claims with different
evidential status, and they must not be conflated:

- **The antisymmetric readout is a structural control, not a reasoning claim,
  and it is T4 by the same logic as the relation-consistent decoder** — its
  side-swap equivariance is exact by construction, not learned. What elevates
  it above a bare T4 projection is that its *accuracy* (not just its
  invariance) was independently measured on data never used to build it: the
  350-pair CrossVul external-source audit and five held-out nuisance-transform
  families (context window, split view, git-native Myers/histogram diff,
  whitespace/comment reindent). Canonical accuracy under the antisymmetric
  decision held up on every one of those T2-style checks, so "transferable
  structural fix" is a T2 claim, not merely T4.
- **The fine-tuning increment over that structural null is not validated as a
  transferable learned repair.** It reached significance in-distribution
  (PrimeVul, McNemar p=0.002) but failed both preregistered transfer legs:
  CrossVul (p=0.508, not significant) and the nuisance-transform battery (no
  family clears the Bonferroni-corrected threshold p<0.01 for five families
  tested; two families show the fine-tuned model performing *worse* than the
  frozen baseline). A sign-reversing effect across held-out conditions is
  evidence against a real transferable signal, not merely an absence of proof
  for one — do not report this increment as a validated repair, and do not
  promote it into a headline claim above the structural-fix result.

**Claim boundary to reuse verbatim:** *The antisymmetric readout provides a
transferable structural constraint for side-order consistency. However, the
fine-tuning increment over this structural null does not survive
external-source or nuisance-transform transfer, so the current learned repair
objective remains unresolved.*

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
