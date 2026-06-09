# Relational Benchmark V2

## Purpose

This benchmark replaces the earlier sorted-first counterfactual pilot with a
reviewer-facing paired measurement protocol. It tests whether secure patch
predictions obey expected relations under controlled prompt transformations,
while recording when token truncation changes the evidence available to the
model.

## Materialized Benchmark

| Item | Value |
| --- | ---: |
| Pair groups | 600 |
| Sources | PrimeVul 200, DeltaSecommits 200, PatchEval 200 |
| Base rows | 600 |
| Intervention rows | 4,200 |
| Sampling | seeded stratified, seed 42 |
| Maximum model length | 512 tokens |

Sampling is stratified by language, CWE, diff-size bucket, token-length
bucket, project, and year. Canonical side order is deterministic and does not
depend on input row order.

## Transformation Tiers

Validated v2 transformations include metadata removal, neutral end padding,
neutral pre-diff padding, canonical side-order swap, and controlled 25/50/75%
context-budget pressure. Regex identifier renaming and generic formatting
normalization are excluded until parser-aware implementations can validate
syntax and changed-region fidelity.

## Truncation Diagnostic

| Template | New critical-hunk truncations |
| --- | ---: |
| Metadata removal | 0 / 600 |
| End padding | 0 / 600 |
| Canonical side swap | 0 / 600 |
| Pre-diff numbered padding | 36 / 600 |
| 25% context pressure | 30 / 600 |
| 50% context pressure | 65 / 600 |
| 75% context pressure | 94 / 600 |

This changes the interpretation of the v1 padding result. Sensitivity to
pre-diff padding can combine nuisance sensitivity with a loss of visible
security evidence. V2 therefore reports clean no-truncation invariance and
context-pressure degradation separately.

## Evaluation

`scripts/evaluate_relational_benchmark_v2.py` reports relation violation,
transformed and robust accuracy, probability relation error, directional
bias, no-truncation results, per-template metrics, and pair-key cluster
bootstrap intervals.

## Claim Boundary

V2 is a controlled relational robustness benchmark, not proof of semantic
invariance under every code transformation. The next valid step is a frozen
cross-model evaluation on this instrument, followed by parser-aware
identifier and formatting interventions.
