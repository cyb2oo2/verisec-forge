# Frozen-Backbone Readout Control

One terminal-trained Qwen backbone and LoRA representation is frozen. Only matched linear heads are trained over terminal, mean, or changed-hunk pooled hidden states.

## Per-Seed Endpoints

| readout | seed | canonical | suffix | swap | baseline | both correct | fallback |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `terminal` | 7 | 65.00% | 79.22% | 45.56% | 39.78% | 38.33% | 0.00% |
| `terminal` | 123 | 63.89% | 80.74% | 46.11% | 40.63% | 40.00% | 0.00% |
| `mean` | 7 | 63.89% | 88.96% | 30.00% | 33.41% | 27.22% | 0.00% |
| `mean` | 123 | 68.33% | 76.19% | 46.11% | 47.91% | 38.89% | 0.00% |
| `changed_hunk` | 7 | 68.33% | 99.78% | 51.67% | 50.22% | 45.00% | 0.00% |
| `changed_hunk` | 123 | 68.89% | 99.57% | 50.56% | 49.94% | 44.44% | 0.00% |

## Pooled Pair-Cluster Comparisons

| candidate | canonical delta | 95% CI | suffix delta | 95% CI | direct effect | canonical non-inferior |
| --- | ---: | --- | ---: | --- | --- | --- |
| `mean` | +0.0167 | [-0.0417, +0.0750] | +0.0260 | [-0.0281, +0.0823] | no | no |
| `changed_hunk` | +0.0417 | [-0.0333, +0.1194] | +0.1970 | [+0.1418, +0.2554] | yes | no |

## Confidence-Matched Suffix Delta

Pairs are retained when canonical confidence margins differ by at most `0.05`.

| candidate | seed | pairs | coverage | suffix delta | 95% CI |
| --- | ---: | ---: | ---: | ---: | --- |
| `mean` | 7 | 8 | 4.44% | +0.0417 | [-0.1667, +0.3333] |
| `mean` | 123 | 6 | 3.33% | +0.1111 | [-0.2222, +0.4444] |
| `changed_hunk` | 7 | 16 | 8.89% | +0.4375 | [+0.1875, +0.6875] |
| `changed_hunk` | 123 | 15 | 8.33% | +0.3778 | [+0.1778, +0.6000] |

## Source-Wise Suffix Delta

| candidate | source | delta | 95% CI |
| --- | --- | ---: | --- |
| `mean` | `deltasecommits` | -0.1124 | [-0.1705, -0.0620] |
| `mean` | `patcheval` | +0.1242 | [+0.0273, +0.2273] |
| `mean` | `primevul` | +0.0357 | [-0.0625, +0.1399] |
| `changed_hunk` | `deltasecommits` | +0.0194 | [+0.0039, +0.0388] |
| `changed_hunk` | `patcheval` | +0.2788 | [+0.1727, +0.3879] |
| `changed_hunk` | `primevul` | +0.2530 | [+0.1548, +0.3601] |

## Claim Boundary

- Mean pooling does not show a stable direct effect once the representation is frozen; its confirmed training-conditioned gain is therefore consistent with altered gradient flow or learned representations.
- Changed-hunk pooling retains a significant direct suffix gain, supporting structural exclusion of endpoint tokens.
- Confidence-matched results are diagnostic only because coverage is below 10%.
- Canonical non-inferiority is not established, and side-swap reasoning remains unresolved.

This isolates pooling over one frozen terminal-trained Qwen representation. It does not establish model-family generality or solve side-order reasoning.
