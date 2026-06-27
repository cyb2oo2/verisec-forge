# Decoder Stress Validation

## Scope

This report runs the relation-consistent decoder stress validation on the
retained Qwen 1.5B VeriPatch-RR smoke prediction artifact.

Inputs:

- Benchmark: `data/processed/secure_code_relational_benchmark_v2_qwen15b_runtime.jsonl`
- Predictions: `outputs/secure_code_veripatch_rr_qwen15b_smoke_predictions.jsonl`
- JSON report: `reports/decoder_stress_validation_v1.json`

This is a post-hoc structural control report. It is not a new model result, not
a benchmark release, and not a leaderboard row.

It is not evidence that the underlying model has learned stronger secure-patch reasoning.

## Conditions

| Condition | Description |
| --- | --- |
| Baseline | Original retained Qwen smoke predictions. |
| Relation-consistent decoded | Test-time projection over identity, invariant, and side-swap rows using declared relations and `probability_a`. |
| Randomized-base-id decoded | Same decoder after shuffling non-identity rows' `base_id` links as a pairing-structure negative control. |

The decoder does not use `gold_riskier_side`. Context-pressure rows are not
projected.

## Results

| Metric | Baseline | Decoded | Randomized-pair decoded |
| --- | ---: | ---: | ---: |
| Base accuracy | 0.6533 | 0.6567 | 0.5317 |
| End-to-end relation accuracy | 0.6958 | 1.0000 | 0.5967 |
| Robust accuracy | 0.4883 | 0.6567 | 0.3900 |
| Relation violation rate | 0.3042 | 0.0000 | 0.4033 |
| Side-swap consistency | 0.4950 | 1.0000 | 0.5967 |

Stress metrics:

| Metric | Value |
| --- | ---: |
| Relation success delta | +0.3042 |
| Swap consistency gain | +0.5050 |
| Identity distortion rate | 0.0875 |
| Randomized-pair control gap | +0.4033 |
| Projected row coverage | 0.6250 |

Decoder accounting:

| Field | Decoded | Randomized-pair decoded |
| --- | ---: | ---: |
| Input rows | 9,600 | 9,600 |
| Projected rows | 6,000 | 6,000 |
| Skipped rows | 3,600 | 3,600 |
| Label changes | 1,431 | 1,745 |
| Mean probability shift | 0.2261 | 0.2708 |

Skipped rows are context-pressure rows:

```text
unsupported_relation:context_pressure = 3,600
```

## Interpretation Boundary

The decoded condition reaches perfect relation consistency because the operator
projects predictions to satisfy declared identity, invariant, and side-swap
relations. That is expected behavior of the structural decoder.

It is not evidence by itself that the base model reasoned correctly.

The randomized-pair control remains substantially below the decoded condition,
which supports the view that the projection depends on the retained pairing
structure rather than arbitrary smoothing alone. However, the nonzero
randomized-pair score and the 8.75% identity distortion rate show that the
decoder can reshape predictions. Any future paper-facing claim must report
identity distortion and randomized-pair controls alongside relation gains.

## Claim Boundary

Relation-consistent decoding can enforce declared relation structure on this
retained prediction artifact. This report does not claim improved model
reasoning, does not compare models, and does not promote decoder metrics as
ordinary vulnerability-detection accuracy.

This report does not claim improved model reasoning.
