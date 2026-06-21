# Paper 1 Draft Outline

Canonical paper-facing files now live under [`paper/`](../paper/README.md).
This document is retained as the earlier outline snapshot; use
[`paper/outline.md`](../paper/outline.md) and
[`paper/main_claims.md`](../paper/main_claims.md) for PR #11 onward.

## Working Title

**When Secure Patch Models Change Their Mind: Relational Evaluation and
Readout-Induced Endpoint Sensitivity**

Alternative:

**Pointwise Accuracy Is Not Relational Reasoning: Auditing Secure Patch
Models Under Pair and Context Transformations**

## Central Claim

High pointwise secure-patch accuracy can coexist with relationally
inconsistent decisions. VeriPatch-RR exposes these failures, and controlled
readout interventions show that terminal-context sensitivity can be reduced
without producing side-order reasoning.

## Contributions

1. **Pointwise accuracy misses relational failure.** Same-source and
   pointwise performance do not guarantee consistent vulnerable/fixed pair
   decisions under side order changes.
2. **VeriPatch-RR measures relational robustness.** The benchmark separates
   side-order equivariance, nuisance invariance, endpoint sensitivity,
   context pressure, critical-hunk visibility, both-directions-correct, and
   robust accuracy.
3. **Endpoint robustness is readout-controlled but distinct from side-order
   reasoning.** The finding appears in cross-architecture controls, a
   same-backbone intervention, and an independent new-pair/new-template/
   new-seed confirmation.

## Sections

### 1. Introduction

Motivating tension:

> A model can classify individual secure patches above chance while failing
> to preserve the vulnerable/fixed relation under transformations that
> should not change the decision.

### 2. Problem Formulation

Define:

- pointwise correctness;
- side-order equivariance;
- marginal-conditioned independence baseline;
- nuisance invariance;
- endpoint robustness;
- both-directions-correct;
- robust accuracy.

### 3. VeriPatch-RR

Describe:

- PrimeVul, DeltaSecommits, and PatchEval;
- representative and stress suites;
- canonical rendering;
- model-specific tokenizer visibility;
- transformation validation tiers;
- pair-cluster statistics.

### 4. Diagnosing Relational Failure

Report:

- same-source shortcut diagnosis;
- Qwen frozen-instrument smoke;
- side-swap inconsistency;
- endpoint directional sensitivity;
- representation versus relational failure on DeltaSecommits.

### 5. Cross-Architecture Evidence

Report:

- Qwen decoder classifier;
- CodeBERT encoder classifier;
- exact training-contract controls;
- marginal-conditioned baselines;
- endpoint gap on clean, both-correct, and confidence-near-matched subsets.

### 6. Readout Mechanism

Report:

- terminal, first-token, mean, changed-hunk, and fixed-anchor discovery;
- invalid first-token causal-decoder control;
- independent 180-pair confirmation;
- frozen-backbone matched-head control.

### 7. Independent Confirmation

Report:

- zero discovery pair overlap;
- unseen suffix templates;
- seeds 7 and 123;
- pair-bootstrap suffix deltas;
- failed canonical non-inferiority;
- public artifact bundle.

### 8. Limitations

State explicitly:

- broad model-family generality is limited;
- canonical non-inferiority is not established;
- bootstrap CIs are conditional on selected seeds;
- no independent human-gold evidence spans;
- side-order reasoning remains unresolved;
- changed-hunk pooling uses task structure;
- frozen-backbone control uses one terminal-trained Qwen representation.

### 9. Discussion

Main conclusion:

> Relational robustness is multidimensional. Endpoint invariance can be
> engineered without producing side-order reasoning.

## Main Tables And Figures

1. Progressive control table: same-source headline to paired controls.
2. VeriPatch-RR metric and intervention taxonomy.
3. Qwen/CodeBERT cross-architecture comparison.
4. Endpoint gap and terminal-phrase interaction figure.
5. Same-backbone discovery and independent confirmation table.
6. Frozen-backbone readout-control table.
7. Source-wise suffix-delta forest plot.
8. Discovery-to-confirmation study diagram.
9. Claim-boundary table.

## Excluded From Main Contributions

- additional source-router variants;
- threshold optimization and new abstention sweeps;
- agent/UI expansion;
- antisymmetric side-order architecture;
- evidence grounding without independent human gold.

These remain secondary diagnostics or Paper 2 directions.
