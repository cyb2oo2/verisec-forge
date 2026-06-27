# Decoder Failure Case Audit

## Scope

This audit examines identity rows changed by the relation-consistent
decoder on the retained Qwen 1.5B VeriPatch-RR smoke prediction
artifact. It focuses on decoder side effects, especially identity
distortion.

Gold labels are used only to audit consequences of identity flips after
decoding. They are not used by the decoder.

This audit explains where the decoder reshapes identity predictions. It
does not change the decoder, benchmark, or model.

## Inputs

- Benchmark: `data/processed/secure_code_relational_benchmark_v2_qwen15b_runtime.jsonl`
- Predictions: `outputs/secure_code_veripatch_rr_qwen15b_smoke_predictions.jsonl`
- JSON report: `reports/decoder_failure_case_audit_v1.json`

## Identity Distortion Summary

| Metric | Value |
| --- | ---: |
| Identity rows | 1,200 |
| Distorted identity rows | 105 |
| Identity distortion rate | 0.0875 |
| Flips toward gold | 55 |
| Flips away from gold | 50 |

## Flip Outcome Decomposition

| Outcome | Count |
| --- | ---: |
| correct_to_correct_unchanged | 721 |
| correct_to_wrong | 50 |
| wrong_to_correct | 55 |
| wrong_to_wrong_unchanged | 374 |

## Driver Categories

| Likely driver | Count |
| --- | ---: |
| ambiguous_near_threshold_projection | 4 |
| invariant_view_overrides_identity | 8 |
| low_identity_margin | 18 |
| multi_view_majority_overrides_identity | 67 |
| swap_view_overrides_identity | 8 |

Driver labels are heuristics over identity margin, canonical projection
margin, and cross-view probability disagreement. They are diagnostic
tags, not causal proof.

## Representative Failure Cases

| ID | Outcome | Driver | Baseline | Decoded | Gold | Identity margin | Cross-view range |
| --- | --- | --- | --- | --- | --- | ---: | ---: |
| `balanced_stress::primevul::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784::base` | correct_to_wrong | multi_view_majority_overrides_identity | B | A | B | 0.4952 | 0.9906 |
| `balanced_stress::primevul::furnace|0eb02422d5161767e9983bdaa5c429762d3477ce|CVE-2022-1289::base` | correct_to_wrong | multi_view_majority_overrides_identity | B | A | B | 0.4832 | 0.9745 |
| `balanced_stress::deltasecommits::deltasecommits-1499::base` | correct_to_wrong | multi_view_majority_overrides_identity | A | B | A | 0.4627 | 0.9447 |
| `balanced_stress::deltasecommits::deltasecommits-775::base` | correct_to_wrong | multi_view_majority_overrides_identity | A | B | A | 0.4579 | 0.9559 |
| `representative::deltasecommits::deltasecommits-1483::base` | correct_to_wrong | multi_view_majority_overrides_identity | A | B | A | 0.4532 | 0.9525 |
| `representative::deltasecommits::deltasecommits-760::base` | correct_to_wrong | multi_view_majority_overrides_identity | A | B | A | 0.4450 | 0.9164 |
| `balanced_stress::deltasecommits::deltasecommits-1154::base` | correct_to_wrong | swap_view_overrides_identity | B | A | B | 0.4352 | 0.9352 |
| `representative::deltasecommits::deltasecommits-1154::base` | correct_to_wrong | swap_view_overrides_identity | B | A | B | 0.4352 | 0.9352 |
| `balanced_stress::deltasecommits::deltasecommits-1498::base` | correct_to_wrong | multi_view_majority_overrides_identity | B | A | B | 0.4284 | 0.8701 |
| `representative::deltasecommits::deltasecommits-1498::base` | correct_to_wrong | multi_view_majority_overrides_identity | B | A | B | 0.4284 | 0.8701 |

## Interpretation Boundary

This audit does not claim that all distorted rows are fixed or harmed by
the decoder. Correctness labels are used after the fact to categorize
flip consequences. The decoder itself still uses only declared expected
relations and model probabilities.

The audit shows where relation-consistent projection can trade identity
behavior for cross-view consistency. It should be read alongside
`reports/DECODER_STRESS_VALIDATION.md`, not as a standalone model quality result.

This report does not claim improved model reasoning.
