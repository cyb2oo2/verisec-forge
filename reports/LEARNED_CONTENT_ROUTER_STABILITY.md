# Learned Content Router Stability

This report stress-tests diff-body-only source/expert routing under multi-seed pair-group subsampling.

## Protocol

- Router: `multinomial naive bayes over diff-body-only text`
- Feature mode: `diff_line_markers`
- Seeds: `[7, 42, 123]`
- Train fractions: `[0.5, 1.0]`
- Sampling unit: `pair_key within each source`

## Stability Summary

| Train fraction | Route row acc mean/range | Routed BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range | Routed group all-correct mean/range |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.5` | `0.8382 [0.837, 0.8388]` | `0.8634 [0.8627, 0.8638]` | `0.0043 [0.0036, 0.0047]` | `-0.003 [-0.0037, -0.0026]` | `0.8507 [0.8497, 0.8519]` |
| `1.0` | `0.8366 [0.8366, 0.8366]` | `0.8642 [0.8642, 0.8642]` | `0.0051 [0.0051, 0.0051]` | `-0.0022 [-0.0022, -0.0022]` | `0.8504 [0.8504, 0.8504]` |

## Per-Source Tradeoff At Full Training Fraction

| Source | Route acc mean/range | Learned BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range |
| --- | ---: | ---: | ---: | ---: |
| `PrimeVul-time` | `0.7689 [0.7689, 0.7689]` | `0.8803 [0.8803, 0.8803]` | `-0.0006 [-0.0006, -0.0006]` | `-0.0032 [-0.0032, -0.0032]` |
| `DeltaSecommits` | `0.8853 [0.8853, 0.8853]` | `0.8563 [0.8563, 0.8563]` | `0.0077 [0.0077, 0.0077]` | `0.0 [0.0, 0.0]` |
| `PatchEval` | `0.974 [0.974, 0.974]` | `0.8271 [0.8271, 0.8271]` | `0.0185 [0.0185, 0.0185]` | `-0.0019 [-0.0019, -0.0019]` |

## Interpretation

This stability report is a router-level stress test, not a new detector training result. If routed BA stays close to the full-data run under subsampling, the source-router claim is more stable; if per-source deltas vary, the honest claim should emphasize source-specialization tradeoffs rather than universal routing gains.
