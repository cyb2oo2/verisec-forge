# Qwen Relational Mechanism Audit

This audit tests mechanism hypotheses for one PrimeVul-trained Qwen2.5-Coder-1.5B binary side classifier. It does not establish that all secure-code models share these failures.

The checkpoint does not support abstention. All results below measure forced binary decisions; abstention rate is not applicable.

## Headline

| length | canonical accuracy | side-swap equivariance | post-diff relation | post-diff A->B / B->A |
| ---: | ---: | ---: | ---: | ---: |
| 512 | 65.50% | 49.67% | 56.50% | 260 / 1 |
| 1024 | 66.00% | 48.50% | 42.67% | 343 / 1 |

## Findings

1. **Longer context does not repair relational inconsistency.** Canonical accuracy changes only from 65.50% to 66.00%, while side-swap equivariance changes from 49.67% to 48.50%.
2. **The suffix failure is endpoint-sensitive rather than a truncation artifact.** At 1024, post-diff padding has 42.67% relation accuracy with zero transformation-introduced critical-hunk truncations. Restoring a natural ending raises it to 90.50%, whereas a novel `[END_PATCH]` marker reaches only 67.00%.
3. **Prompt distribution shift is secondary.** At 1024, no-metadata and training-contract prompts preserve 90.83% and 89.33% of canonical decisions.
4. **Delta has both representation and relational failures.** At 1024, separator expansion raises forced-decision accuracy from 47.00% to 75.00%, but its side-swap equivariance is only 52.50% and post-diff relation accuracy is 8.00%.

## Padding Position

| length | variant | relation | clean relation | A->B | B->A | new truncation |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 512 | `padding_prompt_prefix` | 82.33% | 91.05% | 80 | 26 | 48 |
| 512 | `padding_after_instructions` | 81.17% | 89.49% | 88 | 25 | 48 |
| 512 | `padding_pre_diff` | 77.83% | 85.46% | 107 | 26 | 48 |
| 512 | `padding_mid_diff` | 75.17% | 80.98% | 123 | 26 | 48 |
| 512 | `padding_post_diff` | 56.50% | 47.27% | 260 | 1 | 0 |
| 512 | `padding_post_diff_restored_ending` | 90.33% | 88.28% | 44 | 14 | 0 |
| 512 | `padding_post_diff_end_patch` | 70.83% | 64.65% | 173 | 2 | 0 |
| 1024 | `padding_prompt_prefix` | 89.33% | 90.48% | 58 | 6 | 5 |
| 1024 | `padding_after_instructions` | 88.50% | 89.77% | 64 | 5 | 5 |
| 1024 | `padding_pre_diff` | 86.00% | 87.13% | 79 | 5 | 5 |
| 1024 | `padding_mid_diff` | 82.50% | 83.42% | 99 | 6 | 5 |
| 1024 | `padding_post_diff` | 42.67% | 39.86% | 343 | 1 | 0 |
| 1024 | `padding_post_diff_restored_ending` | 90.50% | 90.03% | 37 | 20 | 0 |
| 1024 | `padding_post_diff_end_patch` | 67.00% | 65.38% | 193 | 5 | 0 |

## Prompt Contract

| length | variant | accuracy | relation to canonical | clean relation |
| ---: | --- | ---: | ---: | ---: |
| 512 | `canonical` | 65.50% | 100.00% | 100.00% |
| 512 | `canonical_no_metadata` | 64.50% | 86.33% | 92.32% |
| 512 | `training_prompt` | 63.50% | 86.33% | 91.31% |
| 1024 | `canonical` | 66.00% | 100.00% | 100.00% |
| 1024 | `canonical_no_metadata` | 66.17% | 90.83% | 93.01% |
| 1024 | `training_prompt` | 63.67% | 89.33% | 90.56% |

## Delta Representation

| length | representation | accuracy | swap equivariance | post-diff relation | post-diff A->B / B->A | mean tokens | changed lines |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 512 | `delta_raw` | 49.00% | 13.50% | 40.50% | 119 / 0 | 600.0 | 00-02:200 |
| 512 | `delta_separator_expanded` | 74.50% | 49.00% | 16.50% | 153 / 14 | 447.1 | 00-02:57, 03-05:50, 06-10:45, 11-25:35, 26+:13 |
| 512 | `delta_clang_format` | 63.50% | 44.50% | 22.00% | 143 / 13 | 570.4 | 00-02:51, 03-05:44, 06-10:45, 11-25:40, 26+:20 |
| 1024 | `delta_raw` | 47.00% | 4.00% | 10.50% | 179 / 0 | 600.0 | 00-02:200 |
| 1024 | `delta_separator_expanded` | 75.00% | 52.50% | 8.00% | 181 / 3 | 447.1 | 00-02:57, 03-05:50, 06-10:45, 11-25:35, 26+:13 |
| 1024 | `delta_clang_format` | 70.00% | 43.00% | 9.00% | 181 / 1 | 570.4 | 00-02:51, 03-05:44, 06-10:45, 11-25:40, 26+:20 |

## Claim Boundary

- `512` and `1024` are sensitivity settings for the same checkpoint, not separate trained models.
- Relation metrics are also reported on the clean subset where the canonical and transformed critical hunks are both fully visible.
- DeltaSecommits should be described as a combined source and representation shift unless normalization clearly restores behavior.
- Suffix effects are mechanism evidence only if they persist without transformation-introduced truncation; they do not by themselves identify a specific pooling implementation.
