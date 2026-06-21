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
- exact-training-contract prompt swap;
- marginal-conditioned independence baselines;
- endpoint gap and terminal phrase interaction.

Main message: side-order inconsistency appears in both architectures, while
severe terminal endpoint collapse is architecture dependent.

## 6. Readout Mechanism

Report three levels:

- discovery readout ablation;
- independent confirmation on new pairs, unseen suffix templates, and new
  linear-head seeds;
- frozen-backbone matched-head control.

Main message: endpoint robustness can be controlled, but side-order reasoning
does not follow from endpoint robustness.

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
