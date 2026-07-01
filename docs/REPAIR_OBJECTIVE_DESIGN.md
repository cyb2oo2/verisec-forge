# Repair Objective Design

Design for repairing the representation-induced relational failure diagnosed in
the side-order arc: the classifier's candidate-identity decision is causally
sensitive to diff-hunk polarity
(`reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`,
`reports/POLARITY_GOLD_CONFOUND.md`). This document fixes the objective,
architecture, baselines, and success criteria **before** any training run
(Step 4). Reference implementation: `src/vrf/antisymmetric_pair_head.py`.

This is **not** "make the model ignore diff format." Diff structure is
legitimate patch information the encoder should use. The goal is to stop the
model binding its *candidate-identity* judgment to one rendering direction.

## Design constraints from the diagnosis

Three measured facts constrain the design:

1. **Swap-equivariance should be exact, not learned.** Canonical vs side-swap
   predictions are ~independent (`phi=-0.024`). A soft penalty invites the model
   to approximate a symmetry it could instead be given for free.
2. **Naive both-orientation augmentation is insufficient.** Training was already
   orientation-balanced 3000/3000 with every pair in both renderings and still
   failed (`reports/POLARITY_GOLD_CONFOUND.md`). The repair must add something
   augmentation does not.
3. **Consistency is gameable by collapse.** A constant predictor has zero
   violation rate. The objective must carry a pointwise term and a
   collapse guard, and per-class accuracy must be reported regardless
   (`docs/EVIDENCE_HIERARCHY.md`).

## Architecture: symmetric encoder, antisymmetric readout

A weight-shared joint encoder produces an order-dependent feature `h(X, Y)` for
"candidate X in the Side-A slot, Y in the Side-B slot". `h` attends across both
candidates and over the diff hunk -- **diff structure is kept**. The score is

    s(A, B) = w . ( h(A, B) - h(B, A) )         # antisymmetric readout

so `s(A,B) = -s(B,A)` by construction (`antisymmetric_score`, tested). With
`P(A riskier) = sigmoid(s)`, side-swap is exactly equivariant:
`P(riskier | swapped) = 1 - P`.

**The trap this avoids.** Enforcing antisymmetry by scoring candidates
independently (`s = f(A) - f(B)` with a per-candidate `f`) also guarantees the
symmetry -- but deletes all cross-candidate interaction, throwing away the diff
signal we argued is legitimate. Here antisymmetry lives *only in the readout*;
the interaction stays in `h`. An ablation (`s = f(A) - f(B)`) measures what the
interaction is worth.

**What antisymmetry does not fix: polarity.** Reversing the diff rendering
changes `h` unless the input is canonicalized or an invariance loss is applied.
Antisymmetry gives swap-equivariance, not polarity-invariance; conflating them
would be the same category error the task-formulation doc warns about.

## Objective

`repair_loss` (reference impl) combines:

| Term | Purpose | Notes |
| --- | --- | --- |
| `pairwise_bce` | pointwise correctness on the gold side | must not regress; the anchor |
| `polarity_invariance` | `(s_canonical - s_polarity_flipped)^2`, gold/order fixed | the term that targets the measured failure |
| `collapse_penalty` | marginal-balance + variance-floor guard | guard, not a fix |

Swap-equivariance is **not** a loss term -- it is architecturally exact
(`swap_equivariance_residual` asserts it stays 0). Optionally add a label-only
term (predictions invariant to the "Side A"/"Side B" words, already shown inert)
as a cheap regularizer, but it is not load-bearing.

Weighting: start `lambda_polarity = 1.0`, `lambda_collapse = 0.1`, tune
`lambda_polarity` on the validation polarity-invariance/pointwise trade-off.

## Baselines (required; a skeptic will demand each)

1. **Plain both-orientation augmentation** -- already in the training data;
   include as the primary baseline the repair must beat **on transfer**, not
   in-distribution.
2. **Test-time symmetrization (TTA)** -- average/antisymmetrize an *unchanged*
   model at inference. This is the null for "did the representation change?"
3. **Unconstrained head ablation** -- same encoder, generic readout + soft
   equivariance penalty, to show the hard constraint matters.
4. **Independent-scoring ablation** (`f(A)-f(B)`) -- shows the cross-candidate
   interaction is worth keeping.
5. **Frozen-backbone matched-head** -- reuse the existing control
   (`reports/FROZEN_BACKBONE_READOUT_CONTROL.md`) to separate representation
   change from head change.
6. **Constant / majority predictor** -- the degeneracy floor.

## Success criteria (preregistered)

A repair is credible only if **all** hold, on **raw single-pass** predictions
(no TTA, no decoder projection):

- **Canonical non-inferiority:** canonical accuracy delta `>= -0.02` with the CI
  lower bound above `-0.02` (the bar prior readout work failed -- hold repair to
  it).
- **Polarity-invariance improves:** `polarity_only_swap` accuracy rises and the
  score gap `(s_canonical - s_polarity_flipped)` shrinks, CI excluding 0.
- **Side-swap equivariance:** exact by construction; assert residual ~0 and that
  raw `side_swap` accuracy tracks canonical.
- **Violation rate below its marginal-conditioned baseline**
  (`marginal_conditioned_violation_baseline`), CI excluding the baseline.
- **No degeneracy:** per-class accuracy balanced; prediction variance above the
  guard floor.
- **Transfer:** improvement holds on **nuisance transforms not trained on**
  (diff context size, unified vs split, Myers vs histogram, whitespace/comment
  reorder) and on an **external source** (CrossVul relational subset). This is
  the test that separates a real repair from regularizing toward the training
  transforms.

## Distinguishing a real repair from an artifact

| Looks like repair but isn't | How this design rules it out |
| --- | --- |
| Test-time symmetrization | headline metrics are raw single-pass; TTA is a separate labeled row |
| Decoder projection | the relation-consistent decoder (T4) is never in the headline path |
| Constant/degenerate predictor | collapse guard + mandatory per-class accuracy |
| Overfit to trained transforms | success requires transfer to held-out nuisance transforms + external source |
| Consistency bought with accuracy | pointwise BCE reported alongside; canonical non-inferiority gate |

## Scope

Design + reference implementation only; no training here. Step 4 ports
`repair_loss` to the torch training path and runs the preregistered evaluation.
