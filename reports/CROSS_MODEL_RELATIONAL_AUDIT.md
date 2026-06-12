# Cross-Model Relational Audit

This is the first compact architecture comparison on 600 fixed pairs and six variants per pair.

| model | canonical | swap equivariance | post-diff relation | terminal phrase relation | A->B / B->A | robust | clean robust | canonical truncated |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `qwen15b_decoder_classifier` | 65.50% | 49.67% | 56.50% | 90.33% | 260 / 1 | 19.33% | 18.00% | 105 |
| `codebert_encoder_classifier` | 67.67% | 50.17% | 94.17% | 94.50% | 35 / 0 | 38.67% | 28.67% | 178 |

## Findings

- **Relational inconsistency crosses architectures.** Both classifiers remain near chance on side-swap equivariance despite above-chance canonical accuracy.
- **Severe endpoint collapse does not cross this first architecture control.** CodeBERT preserves `94.17%` of canonical decisions under post-diff padding, versus Qwen's `56.50%`.
- **Base capability does not explain the endpoint gap.** CodeBERT canonical accuracy is `67.67%`, close to Qwen's `65.50%`.
- **The readout hypothesis is strengthened but not proven.** The result is consistent with terminal-token decoder readout sensitivity, but pretraining, tokenizer, capacity, and initialization also differ.
- The models do not have identical pretraining, capacity, tokenizer, or initialization; conclusions must remain architecture-stress observations.

## Claim Boundary

CodeBERT uses the same 6,000 bidirectional side-choice rows and one epoch, but Qwen additionally inherits an earlier pair-diff initialization. This is an architecture stress comparison, not a controlled pretraining or capacity comparison.
