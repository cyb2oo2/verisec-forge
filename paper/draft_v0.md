# Pointwise Accuracy Is Not Relational Reasoning

## Abstract

Secure-code models are commonly evaluated with pointwise vulnerability or patch
labels, but high pointwise accuracy can hide failures in relational reasoning.
We study this gap with VeriPatch-RR, a paired vulnerable/fixed patch benchmark
that tests whether model decisions remain consistent under side swaps, suffix
perturbations, context pressure, and model-specific runtime visibility
constraints.

Across a Qwen decoder classifier and a CodeBERT encoder classifier, we find
that pointwise competence does not imply side-order consistency. Both models
remain close to marginal-conditioned independent-decision baselines under side
swaps, even when evaluated with each model's own training contract. However,
severe terminal-context collapse is architecture dependent: Qwen is strongly
affected by post-diff endpoint text, while the CodeBERT first-token encoder
control is not. A minimal broad-replication layer further extends the audit to
a non-Qwen decoder classifier and a generative no-classification-head judge.
These additional models show severe relational stress failures, but their low
canonical accuracy limits broad universal claims.

We then isolate the Qwen readout mechanism. Same-backbone readout ablations and
an independent confirmation set show that endpoint robustness can be controlled
by readout-conditioned training, but this does not solve side-order reasoning.
A frozen-backbone matched-head control further separates mechanisms: mean
pooling's suffix benefit largely disappears when the terminal-trained Qwen+LoRA
representation is held fixed, while changed-hunk pooling retains a direct
suffix-consistency gain. These results support a bounded claim: endpoint
robustness is controllable, but secure patch relational reasoning remains a
distinct unresolved capability.

## 1. Introduction

Security patch review is inherently comparative. A reviewer often asks which
side of a vulnerable/fixed pair carries the risk, what code evidence supports
that decision, and whether the answer would remain stable if the vulnerable and
fixed sides were presented in the opposite order. Standard secure-code model
benchmarks rarely test this relation directly. They usually ask whether a
single function, commit, or snippet is vulnerable. That pointwise framing is
useful, but it can overstate what a model has learned.

This paper studies the gap between pointwise secure-code accuracy and
relational patch understanding. The central observation is simple: a model can
look competent on individual examples while behaving like two nearly
independent classifiers when the sides of a patch pair are swapped. If Side A
is vulnerable in the canonical rendering, then after an exact A/B swap the
riskier side should also swap. A model that fails this test is not merely
making an ordinary classification error; it is failing a structural property
of the task.

We introduce VeriPatch-RR, a tokenizer-neutral relational robustness benchmark
for secure patch reasoning. VeriPatch-RR renders paired vulnerable/fixed
patches under controlled transformations, materializes runtime visibility for
each model tokenizer, and reports side-order, endpoint, context-pressure, and
critical-hunk visibility metrics separately. The benchmark is designed not to
produce a single leaderboard number, but to expose which part of a model's
behavior is reliable.

Our results support three claims. First, ordinary high scores can be
artifact-sensitive: same-source PrimeVul detection reaches `0.9524` accuracy,
but paired controls reveal why that number should not be treated as semantic
patch understanding. Second, pointwise competence and relational consistency
are separable: Qwen and CodeBERT both show incomplete side-order reasoning,
while terminal endpoint collapse is much stronger in Qwen than in the encoder
control. Third, readout design can control endpoint sensitivity, but it does
not automatically produce side-order reasoning.

The intended contribution is therefore not a new vulnerability scanner. It is
a measurement and mechanism study: VeriPatch-RR shows how secure-patch models
can fail under relation-preserving transformations, and why evaluation should
measure those failures directly.

## 2. Problem Formulation

We consider a paired patch example with two rendered sides, Side A and Side B.
Exactly one side is riskier under the benchmark label. A model outputs a
decision in `{A, B}`, or in some settings an abstention such as
`INSUFFICIENT_CONTEXT`.

Pointwise accuracy measures whether the model selects the gold riskier side
for a single rendering. This is the conventional metric, but it does not test
whether the model understands the relation between the two sides.

Side-order equivariance measures whether the model flips its decision when the
two sides are swapped. If a canonical rendering has gold label `A`, the swapped
rendering should have gold label `B`. A model succeeds only if its predictions
change accordingly.

The marginal-conditioned independence baseline controls for label bias. A
model that predicts `A` or `B` with skewed marginal probabilities can achieve
nonzero flip rates by chance. We therefore compare observed side-swap
equivariance against the flip rate expected from independent canonical and
swapped decisions with the same marginal `B` rates.

Both-directions-correct is stricter than swap equivariance. It requires the
canonical prediction and the swapped prediction to both be correct. This metric
distinguishes structural flipping from reliable task performance.

Endpoint robustness measures whether a model preserves its decision under
semantically irrelevant text appended after the diff. This isolates terminal
context sensitivity from side-order reasoning.

Runtime visibility records whether the changed hunk remains visible under each
model's tokenizer, context length, truncation side, and special-token policy.
This is necessary because a transformation can change tokenization and
therefore hide the evidence a model would need.

## 3. VeriPatch-RR

VeriPatch-RR is a paired vulnerable/fixed patch benchmark built from
PrimeVul, DeltaSecommits, and PatchEval. It contains a representative suite and
a separate balanced-stress suite. The representative suite is the primary
paper-facing result; selected reports use a representative-core filtered
runtime containing canonical, side-swap, and suffix rows.

Each example is rendered as a comparison between Side A and Side B. The main
transformations are:

- canonical pair rendering;
- canonical side swap;
- suffix and endpoint perturbations;
- context-pressure variants that place irrelevant text before or after the
  diff;
- metadata and nuisance interventions used for shortcut diagnosis.

Before inference, VeriPatch-RR materializes model-specific runtime accounting.
This step records token counts, truncation, changed-line visibility, and
whether a transformation introduced critical-hunk truncation. The same text can
have different visibility properties for Qwen, CodeBERT, distilgpt2, or a
generative instruction model, so visibility is part of the experimental
artifact rather than a post hoc explanation.

The evaluator reports relation metrics separately from ordinary accuracy. For
side swaps, it reports observed equivariance, marginal-conditioned independence
baselines, residuals, and both-directions-correct. For endpoint perturbations,
it reports suffix consistency and suffix robust accuracy. This separation is
important because a model can be stable and wrong.

## 4. Benchmark Diagnosis

The project began with a standard vulnerability-detection line, where a
same-source PrimeVul detector reached `0.9524` accuracy. That result looked
strong, but it was not a trustworthy headline. Subsequent paired controls
showed that same-source scores can be artifact-sensitive: project, length,
source distribution, and paired construction choices can create shortcuts that
do not reflect semantic patch understanding.

The key diagnostic was to move from standalone vulnerability detection to
paired vulnerable/fixed reasoning. Negative controls protected this move:
metadata-only balanced accuracy was `0.5022`, candidate-only was `0.5078`, and
counterpart-only was `0.5156`. These near-chance controls make the diff-based
signal more credible.

A diff-only paired detector achieved a three-seed mean balanced accuracy of
`0.8287`. Pair-coupled decoding further improved the strongest system layer to
five-split balanced accuracy `0.8572`, with mean pair-minus-bucket delta
`+0.0348`. This is a useful task-structured system result, but it is not the
central claim of this paper. The central claim is that paired evaluation
changes what we can see: it exposes relation failures that pointwise scores
hide.

## 5. Cross-Model Relational Audit

We next ask whether relational failures are specific to the original Qwen
decoder classifier. The first cross-architecture audit compares a Qwen decoder
classifier with a CodeBERT encoder classifier under the fixed VeriPatch-RR
protocol.

Under exact-training-contract side swaps, Qwen reaches `0.4600` and CodeBERT
reaches `0.5300`. Both are incomplete, and both must be interpreted against
their marginal-conditioned independence baselines rather than against a naive
`0.5` chance line. The result shows that side-order inconsistency is not simply
a prompt wording artifact.

Endpoint behavior differs sharply. CodeBERT preserves post-diff decisions at
`0.9417`, while Qwen falls to `0.5650`, producing an endpoint gap of `+0.3767`
with paired bootstrap 95% CI `[0.3317, 0.4200]`. The gap remains positive on
jointly clean, both-canonical-correct, and confidence-near-matched subsets.
This decomposes two failure modes: side-order relational inconsistency appears
in both architectures, while severe terminal endpoint collapse is architecture
dependent.

PR #12 adds minimal broad replication without turning the study into a model
zoo. The added non-Qwen decoder classifier uses distilgpt2 with a LoRA
sequence-classification head. It reaches canonical accuracy `55.83%`, side-swap
equivariance `9.83%`, marginal-conditioned independence baseline `43.93%`, and
side-swap residual `-0.3410`; both-directions-correct is `6.67%`. This is
stress evidence, not a strong-model result, because canonical accuracy is low.

The generative instruction judge uses strict outputs
`A_RISKIER`, `B_RISKIER`, or `INSUFFICIENT_CONTEXT`. It reaches canonical
accuracy `46.67%`, both-directions-correct `0.50%`, and invalid output rate
`5.00%`. Its prediction distribution is strongly A-biased
(`A=1620`, `B=90`, `INVALID=90`), so its suffix consistency should be
interpreted as decision stability rather than correct relational reasoning.

Together, these results support a bounded generality claim: side-order
relational failure is not confined to the original Qwen classifier. VeriPatch-RR
exposes similar stress failures across multiple mechanisms, including an
encoder classifier, a non-Qwen decoder classifier, and a generative
no-classification-head judge. The evidence does not prove that all strong
secure-code models fail.

## 6. Readout Mechanism

Having separated side-order failure from endpoint collapse, we study whether
Qwen's terminal endpoint sensitivity is caused by readout design. The
same-backbone ablation changes only how the hidden representation is read for
classification. Variants include terminal non-padding token readout,
first-token readout, mean pooling, changed-hunk pooling, and fixed terminal
anchor pooling.

Mean pooling raises post-diff consistency from `0.5533` to `0.8983`.
Changed-hunk pooling reaches `0.9983`. However, neither variant establishes
canonical non-inferiority under the preregistered success rule. The mechanism
result is therefore not that these are better classifiers, but that endpoint
robustness is causally controllable by readout-conditioned training.

An independent confirmation freezes the discovery setting and evaluates 180
new pair IDs, three unseen suffix templates, and seeds `7` and `123`. Mean
pooling improves visible-suffix consistency by `+0.3095` with 95% CI
`[+0.2348, +0.3799]`. Changed-hunk pooling improves it by `+0.4903` with 95%
CI `[+0.4448, +0.5357]`. Both effects are positive across the two seeds, and
changed-hunk fallback is zero. Yet both fail the canonical non-inferiority
criterion, so the confirmed claim remains mechanism control rather than
promoted model improvement.

Finally, a frozen-backbone matched-head control separates representation effects
from pooling effects. Mean pooling's direct suffix benefit shrinks to `+0.0260`
with a CI crossing zero. Changed-hunk pooling retains a direct gain of
`+0.1970`, with 95% CI `[+0.1418, +0.2554]`. This suggests that mean pooling's
benefit is mainly training mediated, while changed-hunk pooling has a more
direct structural effect over the fixed representation.

Most importantly, endpoint robustness does not solve side-order reasoning.
Changed-hunk pooling can nearly eliminate suffix instability while leaving
side-swap behavior near a marginal-conditioned independence baseline. This is
the core mechanism conclusion: endpoint robustness and relational reasoning are
different capabilities.

## 7. Limitations

This work is a measurement study, not a deployed vulnerability scanner. The
artifact should not be used as an automated security review system without
human oversight.

The broad model-family claim is intentionally limited. The strongest
competency-controlled comparison is between the Qwen decoder classifier and the
CodeBERT encoder classifier. The PR #12 distilgpt2 and generative-judge slots
broaden mechanism coverage, but both have low canonical accuracy and should be
treated as stress evidence rather than strong-model universal failure proof.

Readout variants are mechanism evidence, not promoted classifiers. None of the
readout candidates satisfies the preregistered canonical non-inferiority rule.

Bootstrap intervals are conditional on the selected experiment designs, seeds,
and frozen splits. They quantify uncertainty for the stated protocol, not for
all possible secure-code datasets or model families.

Runtime visibility is model-tokenizer specific. Critical-hunk truncation can
weaken direct comparability across architectures and must be reported alongside
relation metrics.

Evidence localization remains diagnostic unless independently human
adjudicated. The current evidence-coupled audit loop is useful for failure
analysis, but it is not yet a gold explanation benchmark.

## 8. Discussion

The main lesson is that secure-patch evaluation should measure relational
consistency, not only pointwise correctness. A model that classifies the
canonical rendering correctly can still fail the structural requirement that
the answer should flip under an A/B side swap. A model that is stable under a
suffix perturbation can still be stably wrong. These are not edge cases; they
are central to whether a model understands patch relations.

VeriPatch-RR is designed to make these distinctions visible. It separates
ordinary accuracy, side-order equivariance, marginal-conditioned independence,
both-directions-correct behavior, endpoint robustness, and runtime visibility.
This decomposition turns a vague complaint that "models are brittle" into
measurable failure modes.

The next method question is not another endpoint readout tweak. The unresolved
capability is side-order structure. Future systems should directly model the
antisymmetry of paired patch decisions, for example through joint A/B scoring,
swap-consistency losses, structured pair decoders, or objectives that optimize
both-directions-correct behavior.

The paper's practical recommendation is modest but important: when evaluating
secure-code models for patch review, include relation-preserving
transformations. If a model cannot preserve the relation between vulnerable and
fixed sides, then pointwise accuracy alone is not enough evidence of secure
patch understanding.
