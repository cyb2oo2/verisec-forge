# Learned Content Router Stability

This report stress-tests diff-body-only source/expert routing under multi-seed pair-group subsampling.

## Protocol

- Router: `multinomial naive bayes over diff-body-only text`
- Feature mode: `token_1_2`
- Seeds: `[7, 42, 123]`
- Train fractions: `[0.5, 1.0]`
- Sampling unit: `pair_key within each source`

## Stability Summary

| Train fraction | Route row acc mean/range | Routed BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range | Routed group all-correct mean/range |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.5` | `0.7358 [0.7262, 0.7447]` | `0.863 [0.8627, 0.8631]` | `0.0039 [0.0036, 0.004]` | `-0.0034 [-0.0037, -0.0033]` | `0.8462 [0.8452, 0.8467]` |
| `1.0` | `0.7324 [0.7324, 0.7324]` | `0.8635 [0.8635, 0.8635]` | `0.0044 [0.0044, 0.0044]` | `-0.0029 [-0.0029, -0.0029]` | `0.8452 [0.8452, 0.8452]` |

## Per-Source Tradeoff At Full Training Fraction

| Source | Route acc mean/range | Learned BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range |
| --- | ---: | ---: | ---: | ---: |
| `PrimeVul-time` | `0.6741 [0.6741, 0.6741]` | `0.8796 [0.8796, 0.8796]` | `-0.0013 [-0.0013, -0.0013]` | `-0.0039 [-0.0039, -0.0039]` |
| `DeltaSecommits` | `0.6606 [0.6606, 0.6606]` | `0.8532 [0.8532, 0.8532]` | `0.0046 [0.0046, 0.0046]` | `-0.0031 [-0.0031, -0.0031]` |
| `PatchEval` | `0.9888 [0.9888, 0.9888]` | `0.829 [0.829, 0.829]` | `0.0204 [0.0204, 0.0204]` | `0.0 [0.0, 0.0]` |

## Interpretation

This stability report is a router-level stress test, not a new detector training result. If routed BA stays close to the full-data run under subsampling, the source-router claim is more stable; if per-source deltas vary, the honest claim should emphasize source-specialization tradeoffs rather than universal routing gains.
