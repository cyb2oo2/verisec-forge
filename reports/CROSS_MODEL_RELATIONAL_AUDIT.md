# Cross-Model Relational Audit

This is the first compact architecture comparison on 600 fixed pairs and eight variants per pair.

| model | canonical | swap | training-contract swap | post-diff | terminal phrase | robust | clean coverage | clean robust conditional | clean+robust coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `qwen15b_decoder_classifier` | 65.50% | 49.67% | 46.00% | 56.50% | 90.33% | 19.33% | 74.50% | 24.16% | 18.00% |
| `codebert_encoder_classifier` | 67.67% | 50.17% | 53.00% | 94.17% | 94.50% | 38.67% | 58.00% | 49.43% | 28.67% |

## Swap Diagnostics

| model | rendering | observed equivariance | independence baseline | observed - baseline | both directions correct |
| --- | --- | ---: | ---: | ---: | ---: |
| `qwen15b_decoder_classifier` | canonical | 49.67% | 49.02% | +0.0064 | 40.67% |
| `qwen15b_decoder_classifier` | exact training contract | 46.00% | 49.07% | -0.0307 | 38.00% |
| `codebert_encoder_classifier` | canonical | 50.17% | 42.20% | +0.0797 | 41.33% |
| `codebert_encoder_classifier` | exact training contract | 53.00% | 44.89% | +0.0811 | 43.00% |

## Paired Statistics

- Endpoint gap, CodeBERT minus Qwen: `0.3767` (pair bootstrap 95% CI `[0.3317, 0.4200]`).
- Terminal-recovery interaction: `0.3350` (pair bootstrap 95% CI `[0.2933, 0.3750]`).

| subset | pairs | endpoint gap | 95% CI | recovery interaction | 95% CI |
| --- | ---: | ---: | --- | ---: | --- |
| `all_pairs` | 600 | 0.3767 | [0.3317, 0.4200] | 0.3350 | [0.2933, 0.3750] |
| `jointly_clean` | 348 | 0.3908 | [0.3247, 0.4511] | 0.3736 | [0.3132, 0.4310] |
| `both_canonical_correct` | 269 | 0.3197 | [0.2639, 0.3755] | 0.2862 | [0.2305, 0.3420] |
| `canonical_confidence_gap_le_0_05` | 148 | 0.2905 | [0.2095, 0.3716] | 0.2635 | [0.1892, 0.3378] |

## By Dataset

| dataset | pairs | endpoint gap | 95% CI | recovery interaction |
| --- | ---: | ---: | --- | ---: |
| `deltasecommits` | 200 | 0.5950 | [0.5300, 0.6650] | 0.5300 |
| `patcheval` | 200 | 0.2900 | [0.2050, 0.3700] | 0.2450 |
| `primevul` | 200 | 0.2450 | [0.1700, 0.3150] | 0.2300 |

## Findings

- **Relational inconsistency crosses architectures.** Both classifiers remain close to their marginal-conditioned independent-decision baselines on canonical and exact-training-contract side-swap equivariance despite above-chance pointwise accuracy.
- **Severe endpoint collapse does not cross this first architecture control.** CodeBERT preserves `94.17%` of canonical decisions under post-diff padding, versus Qwen's `56.50%`.
- **Base capability does not explain the endpoint gap.** CodeBERT canonical accuracy is `67.67%`, close to Qwen's `65.50%`.
- **The readout hypothesis is strengthened but not proven.** The result is consistent with terminal-token decoder readout sensitivity, but pretraining, tokenizer, capacity, and initialization also differ.
- The models do not have identical objectives, pretraining, capacity, tokenizer, or initialization; conclusions must remain architecture-stress observations.

## Claim Boundary

CodeBERT uses the same 6,000 bidirectional side-choice rows and one epoch, but Qwen additionally inherits an earlier pair-diff initialization and uses margin plus complementary-probability regularization. This is an architecture stress comparison, not a controlled architecture-only, objective, pretraining, or capacity comparison.
