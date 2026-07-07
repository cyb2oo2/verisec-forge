# Paper 1 Outline

## Working Title

**Pointwise Accuracy Is Not Relational Consistency: Auditing Secure Patch Models
Under Presentation-Structure Transformations**

Earlier drafts titled this "…Is Not Relational Reasoning"; "reasoning" was
softened to "consistency" because the evidence is behavioral (relation-
consistency metrics), not a claim about internal reasoning
(`docs/REVIEWER_READINESS_AUDIT.md`).

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

- the candidate-identity judgment (which candidate is riskier) vs the
  directional-patch judgment (does this patch fix or introduce), and why diff
  polarity is a nuisance variable under the former and semantic under the
  latter (`docs/TASK_FORMULATION.md`);
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

The label-vs-polarity mechanism decomposition (Section 6) now also has a
competency-matched non-Qwen replication
(`reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md`): CodeBERT
(canonical 0.677 vs. Qwen 0.660) reproduces the ordering -- prose-label swap
inert (phi +0.988 vs. Qwen +0.914), diff-hunk-polarity swap disruptive (phi
−0.193 vs. Qwen −0.094), polarity-only accuracy collapsing 0.677→0.352. This
is two-architecture behavioral evidence, not a universality claim. One nuance
belongs in the writeup: CodeBERT reduces to the crude net-polarity line-count
shortcut on PrimeVul (~0.96 row agreement) where Qwen does not (~0.57) -- the
same behavioral ordering with a different functional form.

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
more likely locus, narrowing but not yet completing the explanation. The
complement (`reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`) completes
it: flipping diff hunk polarity while holding the labels and gold fixed moves
the prediction to near-independence (`phi = -0.094`) and collapses accuracy
from `0.66` to `0.3450` (gold unchanged), whereas relabeling alone did neither
-- localizing the driver to diff hunk polarity (structural content order),
with the polarity-flipped and full-swap predictions agreeing (`phi = +0.892`)
since they share a diff body and differ only in the inert labels. The
interpretation is bounded by `reports/POLARITY_GOLD_CONFOUND.md`: rendering
orientation is de-confounded from gold in both training (balanced `3000/3000`
forward/reverse, every pair in both orientations) and eval, so the collapse is
a genuine relational failure under the candidate-identity task rather than valid
directional inference -- and because both-orientation augmentation is already in
the training data, it is not the fix. Net changed-line polarity nonetheless
stays a spurious-but-predictive feature (`0.706` canonical shortcut accuracy,
inverting to `0.312` under the flip), the standard shortcut-learning setup,
while the model does not reduce to that crude heuristic (~56% row agreement).

## 7. Limitations

State explicitly:

- evidence tiers and the relational-metric reporting contract are defined in
  `docs/EVIDENCE_HIERARCHY.md`; violation rate is only citable raw single-pass,
  with a pair-cluster bootstrap CI, against its marginal-conditioned baseline;
- broad model-family generality is still limited;
- readout variants are mechanism evidence, not promoted classifiers;
- bootstrap intervals are conditional on selected experiment designs;
- frozen-backbone results condition on one Qwen+LoRA representation;
- evidence localization is diagnostic unless independently human adjudicated;
- the learned fine-tuning repair objective is future work: it is not
  validated as a transferable repair (see Section 8).

## 8. Discussion

The paper should end by shifting the field's evaluation question:

> Secure-patch model evaluation should measure relational consistency, not
> only pointwise correctness.

The retained methodological contribution is the **hard antisymmetric readout
as a transferable structural consistency constraint**, not a learned-reasoning
repair, and not another readout tweak in the sense of the pooling-variant
ablations in Section 6 -- it is a structural change to how the two candidates'
scores relate, not a change to how one candidate's hidden state is pooled.
`docs/REPAIR_OBJECTIVE_DESIGN.md` specifies a weight-shared joint encoder with
an antisymmetric readout (`s(A,B) = -s(B,A)` by construction, so side-swap
equivariance is exact rather than penalized). One preregistered
config was trained and evaluated end-to-end
(`reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`): the antisymmetric readout's
canonical accuracy, not only its by-construction invariance, held up on an
external source (CrossVul, 350 pairs) and on five held-out nuisance-transform
families never seen in training (context window, split view, git-native
Myers/histogram diff, whitespace/comment reindent) -- so the structural
constraint is a validated, transferable fix for side-order inconsistency.

The additional fine-tuning objective on top of that readout (pointwise BCE +
explicit polarity-invariance term, since antisymmetry alone does not fix
polarity) is a different claim, and it did not transfer: it was significant
in-distribution (PrimeVul, McNemar p=0.002) but failed both preregistered
transfer tests -- not significant on CrossVul (p=0.508), and clears no family
at a Bonferroni-corrected threshold across the five nuisance transforms, with
two families showing the fine-tuned model performing *worse* than the frozen
baseline. The antisymmetric readout provides a transferable structural
constraint for side-order consistency; the fine-tuning increment over this
structural null does not survive external-source or nuisance-transform
transfer, so the current learned repair objective remains unresolved and is
left as future work: a different objective, more data, or a different readout
parameterization may be needed before re-attempting the learned-repair claim.
