# Task Formulation and the Status of Diff Polarity

This document fixes the claim boundary that the side-order mechanism arc
(`reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`,
`reports/QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`,
`reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`) depends on. Those
reports show the classifier's decision is causally sensitive to diff-hunk
polarity. Whether that is a *shortcut* or *legitimate reading* depends entirely
on the task definition and on how polarity relates to the gold label. Both were
previously implicit. This document makes them explicit and backs them with
measured numbers (`reports/POLARITY_GOLD_CONFOUND.md`,
`scripts/analyze_polarity_gold_confound.py`).

## Two judgments that must not be conflated

**Candidate-identity judgment (what VeriPatch-RR evaluates).**

> Given two code candidates rendered as a unified diff, which candidate
> (Side A or Side B) is riskier / more vulnerable?

The prompt asks exactly this (`Task: compare two related code states and choose
the riskier side. Output one label: A_RISKIER, B_RISKIER, or
INSUFFICIENT_CONTEXT.`) and the external adapter contract returns
`predicted_riskier_side`. Side A and Side B denote fixed code. The answer is a
property of *which candidate* is riskier, not of the direction in which their
difference is rendered.

**Directional-patch judgment (a different task we do not evaluate).**

> Does this rendered patch fix or introduce a vulnerability?

Here the direction of the diff is the object of the question, and `-`/`+`
polarity is semantic content the model *should* use.

The distinction decides how polarity should be treated:

| | candidate-identity | directional-patch |
| --- | --- | --- |
| diff hunk polarity | presentation / nuisance variable | semantic; sensitivity is correct |
| expected behavior under polarity flip (gold fixed) | invariant | may change |
| a prediction flip under polarity-only swap | relational failure | not necessarily a failure |

Because VeriPatch-RR is a candidate-identity task, a prediction that flips when
the *same* pair is shown as a reverse diff (gold held fixed) is a relational
failure. Under a directional-patch task it would not be. **Reviewer-facing
claims about the polarity result are valid only under the candidate-identity
formulation and must say so.**

## Why polarity is a nuisance variable here (not merely by fiat)

Declaring the task to be candidate-identity is not sufficient. A unified diff is
inherently directional, so a skeptic can argue the model is doing valid
directional inference. Two measured facts close that gap
(`reports/POLARITY_GOLD_CONFOUND.md`):

1. **Rendering orientation is de-confounded from gold, by construction and in
   the data.** VeriPatch-RR assigns Side A / Side B independently of which side
   is vulnerable (`build_canonical_pair` uses a stable hash, not the label), so
   the "from"/base side carries no information about gold; the eval gold split
   is ~48.3% A / 51.7% B. The training data that produced the checkpoint is
   *perfectly* orientation-balanced: 3000 forward (`observed`) and 3000 reverse
   (`synthetic_reverse`) rows, vulnerable side exactly 50/50, and **all 2269
   source pairs appear in both orientations**. Naive both-orientation
   augmentation is therefore already present in training and did **not** confer
   polarity-invariance -- a fact the repair direction must take seriously.

2. **Net changed-line polarity is a predictive-but-illegitimate feature.**
   Real security fixes add guards/checks more often than they delete code, so a
   net-additive hunk correlates with which side is vulnerable even though the
   task treats it as nuisance. The crude shortcut "net-added diff -> base side
   riskier; net-removed -> other side" scores **0.855** on the raw training
   pairs and **0.706** on the canonical eval set (P(gold=A | net_added) = 0.82,
   P(gold=A | net_removed) = 0.34). Under a polarity-only swap the identical
   shortcut inverts to **0.312**. This is the textbook spurious-correlation
   setup: a feature that is statistically useful yet task-illegitimate, not a
   non-predictive quirk.

So polarity is a nuisance variable *because* orientation is de-confounded from
gold, while the residual net-polarity correlation is exactly the spurious signal
a robust model must not bind to.

## What we do and do not claim

* The model's riskier-side decision is **behaviorally, causally sensitive** to
  diff-hunk polarity under controlled, gold-preserving input interventions on
  one checkpoint. We use behavioral phrasing; we do **not** claim the model
  internally "binds" to polarity (no probing / activation evidence).
* The model's polarity sensitivity is **real but not reducible to the crude
  net-polarity line-count heuristic**: per-row agreement between the model and
  that heuristic is only ~56%. We therefore report *that* polarity drives the
  decision, not *which* polarity feature does.
* This is a **diagnostic** of representation-induced relational failure within a
  legitimate patch format, and a motivation for a repair objective. It is
  **not** a claim that diff format is bad, that models should ignore diff
  structure, or that secure-patch reasoning is solved.
* Scope: one checkpoint, one context length (1024), 600 pairs,
  observational/correlational; upstream round-3 evidence is AI-pilot-classified
  with human confirmation pending (`reports/RESULTS_INDEX.md`).

## Copyable claim-boundary paragraph

> VeriPatch-RR evaluates a candidate-identity judgment -- given two code states
> rendered as a unified diff, which state (Side A or Side B) is riskier -- not a
> directional-patch judgment ("does this patch fix or introduce a
> vulnerability?"). Under the directional judgment, diff hunk polarity is
> semantic and a model should be sensitive to it; under the candidate-identity
> judgment it is a presentation variable, because Side A and Side B denote fixed
> code regardless of the direction their difference is rendered. We treat
> polarity as a nuisance variable because our benchmark assigns Side A/B
> independently of vulnerability, so rendering orientation carries no
> information about gold (eval gold split 48.3% A / 51.7% B; training is
> orientation-balanced 3000/3000 with every pair in both orientations). A
> polarity-driven change in the riskier-side decision is therefore a relational
> failure rather than a valid directional inference. The residual net
> changed-line polarity remains ~71% correlated with gold on eval because real
> fixes are additive -- a spurious-but-predictive feature, not a non-predictive
> quirk. We report behavioral sensitivity only (no internal-binding claim), and
> the model does not reduce to the crude net-polarity heuristic (~56% row
> agreement). This is a diagnostic, and a possible repair target, for
> representation-induced relational failure in secure patch reasoning -- not a
> claim that diff format is bad or that secure-patch reasoning is solved.
