# Paper 1 Outline

## Working Title

**Pointwise Accuracy Is Not Relational Reasoning: Auditing Secure Patch Models
Under Pair and Context Transformations**

## 1. Introduction

Start from the mismatch between common secure-code benchmarks and patch-review
reasoning. In security review, the question is often comparative: which side
of a vulnerable/fixed pair carries the risk, and should that answer change
when the pair order or irrelevant endpoint text changes?

Core hook:

> A model can look competent on individual examples while behaving like two
> nearly independent classifiers when the vulnerable/fixed sides are swapped.

## 2. Problem Formulation

Define:

- pointwise accuracy;
- side-order equivariance;
- marginal-conditioned independence baseline;
- both-directions-correct;
- endpoint robustness;
- runtime visibility and critical-hunk visibility;
- nuisance transformation tiers.

## 3. VeriPatch-RR

Describe the benchmark as a tokenizer-neutral relational instrument:

- paired vulnerable/fixed examples from PrimeVul, DeltaSecommits, and
  PatchEval;
- canonical rendering and side-swap rendering;
- suffix and context-pressure templates;
- runtime materialization per model tokenizer, context length, truncation side,
  and special-token policy;
- pair-cluster bootstrap and held-out confirmation rules.

## 4. Benchmark Diagnosis

Show why ordinary pointwise results are not enough:

- same-source PrimeVul detector reaches high accuracy;
- paired controls expose artifact sensitivity;
- metadata/candidate/counterpart-only controls remain near chance;
- pair-coupled decoding is a stronger but task-structured system layer.

## 5. Cross-Architecture Relational Audit

Compare:

- Qwen decoder classifier;
- CodeBERT encoder classifier;
- non-Qwen decoder classifier replication slot;
- generative instruction judge replication slot;
- exact-training-contract prompt swap;
- marginal-conditioned independence baselines;
- endpoint gap and terminal phrase interaction.

Main message: side-order inconsistency appears in both architectures, while
severe terminal endpoint collapse is architecture dependent. The PR #12
replication slots broaden this from two trained classifiers toward a minimal
model-family matrix without adding new readout variants.

## 6. Readout Mechanism

Report three levels:

- discovery readout ablation;
- independent confirmation on new pairs, unseen suffix templates, and new
  linear-head seeds;
- frozen-backbone matched-head control.

Main message: endpoint robustness can be controlled, but side-order reasoning
does not follow from endpoint robustness. Directly confirmed by crossing the
two interventions (`reports/QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md`):
the terminal-phrase fix that repairs endpoint-collapse invariance by `+0.48`
(42.67% to 90.50%) only moves side-swap equivariance by `+0.03` (48.83% to
52.17%, `p=0.012`, n=600) -- a ~14x smaller effect, evidence the two failure
modes are largely separable rather than the same underlying mechanism.
Sharpened further (`reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`):
canonical and side-swapped predictions for the same pair are statistically
indistinguishable from independent draws (`phi = -0.024`, `p = 0.56`,
chi-square test, n=600), while the same comparison under a non-swap padding
intervention shows strong positive correlation (`phi = 0.80`, `p < 0.0001`).
The failure under swap is closer to content-blindness specific to the swap
than to confused-but-content-aware reasoning, consistent with
position-specific rather than content-symmetric processing. Decomposed
further (`reports/QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`): swapping
only the "Side A"/"Side B" text labels, holding diff hunk polarity fixed,
leaves the prediction almost unchanged (`phi = 0.91`, accuracy collapses to
`0.3483` -- nearly `1 - 0.66`, consistent with the prediction staying frozen
while gold flips underneath it). This rules out the prose text labels as the
driver and points to diff hunk polarity (structural content order) as the
more likely locus, narrowing but not yet completing the explanation.

## 7. Limitations

State explicitly:

- broad model-family generality is still limited;
- readout variants are mechanism evidence, not promoted classifiers;
- bootstrap intervals are conditional on selected experiment designs;
- frozen-backbone results condition on one Qwen+LoRA representation;
- evidence localization is diagnostic unless independently human adjudicated;
- antisymmetric side-order modeling is future work.

## 8. Discussion

The paper should end by shifting the field's evaluation question:

> Secure-patch model evaluation should measure relational consistency, not
> only pointwise correctness.

The next method question is not another readout tweak. It is whether model
architectures or objectives can enforce side-order structure, such as
antisymmetric pair scoring.
