# Same-Backbone Readout Ablation

| readout | canonical | swap | swap baseline | both correct | post-diff | terminal phrase | robust |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `terminal` | 66.17% | 51.00% | 48.61% | 41.83% | 55.33% | 88.50% | 20.17% |
| `first_token` | 47.33% | 0.17% | 34.23% | 0.00% | 62.33% | 62.50% | 0.00% |
| `mean` | 69.00% | 54.33% | 48.13% | 45.50% | 89.83% | 89.67% | 39.17% |
| `changed_hunk` | 69.83% | 50.17% | 50.02% | 42.00% | 99.83% | 99.83% | 37.67% |
| `fixed_terminal_anchor` | 62.83% | 36.33% | 32.01% | 32.00% | 88.17% | 88.00% | 23.17% |

## Paired Deltas Versus Terminal

| readout | canonical delta | 95% CI | post-diff delta | 95% CI | passes |
| --- | ---: | --- | ---: | --- | --- |
| `first_token` | -0.1883 | [-0.2417, -0.1383] | +0.0700 | [+0.0200, +0.1233] | no |
| `mean` | +0.0283 | [-0.0100, +0.0650] | +0.3450 | [+0.3017, +0.3883] | no |
| `changed_hunk` | +0.0367 | [-0.0083, +0.0817] | +0.4450 | [+0.4050, +0.4850] | no |
| `fixed_terminal_anchor` | -0.0333 | [-0.0833, +0.0150] | +0.3283 | [+0.2883, +0.3700] | no |

## Per-Source Post-Diff Delta

| readout | PrimeVul | DeltaSecommits | PatchEval |
| --- | ---: | ---: | ---: |
| `first_token` | -0.0550 | +0.3500 | -0.0850 |
| `mean` | +0.2150 | +0.5050 | +0.3150 |
| `changed_hunk` | +0.3500 | +0.5950 | +0.3900 |
| `fixed_terminal_anchor` | +0.2000 | +0.5100 | +0.2750 |

## Findings

- Mean and changed-hunk pooling strongly reduce post-diff endpoint sensitivity, but neither meets the preregistered canonical-delta tolerance on the fixed audit.
- First-token pooling collapses because a causal decoder's first token cannot attend to the subsequent diff; its apparent consistency gain is not a valid capability gain.
- Changed-hunk pooling reaches `99.83%` post-diff consistency while side-swap equivariance remains near its marginal-conditioned independence baseline, separating endpoint robustness from side-order reasoning.
- Fixed-terminal-anchor pooling improves endpoint stability but loses canonical accuracy and changes the truncation budget; its clean-subset metrics are therefore not comparable without rematerialized runtime accounting.
- No readout meets the preregistered discovery success rule, so no additional seeds are promoted yet.

## Claim Boundary

This is a same-backbone readout intervention. Seed `42` is discovery-only; any selected readout requires two additional seeds.
