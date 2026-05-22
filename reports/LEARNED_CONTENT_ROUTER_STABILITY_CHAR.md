# Learned Content Router Stability

This report stress-tests diff-body-only source/expert routing under multi-seed pair-group subsampling.

## Protocol

- Router: `multinomial naive bayes over diff-body-only text`
- Feature mode: `char_3_5`
- Seeds: `[7, 42, 123]`
- Train fractions: `[0.5, 1.0]`
- Sampling unit: `pair_key within each source`

## Stability Summary

| Train fraction | Route row acc mean/range | Routed BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range | Routed group all-correct mean/range |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.5` | `0.938 [0.9314, 0.9437]` | `0.8649 [0.8649, 0.8649]` | `0.0058 [0.0058, 0.0058]` | `-0.0015 [-0.0015, -0.0015]` | `0.8534 [0.8534, 0.8534]` |
| `1.0` | `0.9401 [0.9401, 0.9401]` | `0.8649 [0.8649, 0.8649]` | `0.0058 [0.0058, 0.0058]` | `-0.0015 [-0.0015, -0.0015]` | `0.8534 [0.8534, 0.8534]` |

## Per-Source Tradeoff At Full Training Fraction

| Source | Route acc mean/range | Learned BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range |
| --- | ---: | ---: | ---: | ---: |
| `PrimeVul-time` | `0.8982 [0.8982, 0.8982]` | `0.8809 [0.8809, 0.8809]` | `0.0 [0.0, 0.0]` | `-0.0026 [-0.0026, -0.0026]` |
| `DeltaSecommits` | `0.9939 [0.9939, 0.9939]` | `0.8563 [0.8563, 0.8563]` | `0.0077 [0.0077, 0.0077]` | `0.0 [0.0, 0.0]` |
| `PatchEval` | `0.9963 [0.9963, 0.9963]` | `0.829 [0.829, 0.829]` | `0.0204 [0.0204, 0.0204]` | `0.0 [0.0, 0.0]` |

## Interpretation

This stability report is a router-level stress test, not a new detector training result. If routed BA stays close to the full-data run under subsampling, the source-router claim is more stable; if per-source deltas vary, the honest claim should emphasize source-specialization tradeoffs rather than universal routing gains.
