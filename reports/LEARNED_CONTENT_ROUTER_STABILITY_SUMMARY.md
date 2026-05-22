# Learned Content Router Stability Summary

This report summarizes multi-seed pair-group subsampling stability across three diff-body feature views.

## Stability Results

| Feature view | Train fraction | Route row acc mean/range | Routed BA mean/range | Delta vs single BA mean/range | Delta vs oracle BA mean/range | Group all-correct mean/range |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `char_3_5` | `0.5` | `0.938 [0.9314, 0.9437]` | `0.8649 [0.8649, 0.8649]` | `0.0058 [0.0058, 0.0058]` | `-0.0015 [-0.0015, -0.0015]` | `0.8534 [0.8534, 0.8534]` |
| `char_3_5` | `1.0` | `0.9401 [0.9401, 0.9401]` | `0.8649 [0.8649, 0.8649]` | `0.0058 [0.0058, 0.0058]` | `-0.0015 [-0.0015, -0.0015]` | `0.8534 [0.8534, 0.8534]` |
| `token_1_2` | `0.5` | `0.7358 [0.7262, 0.7447]` | `0.863 [0.8627, 0.8631]` | `0.0039 [0.0036, 0.004]` | `-0.0034 [-0.0037, -0.0033]` | `0.8462 [0.8452, 0.8467]` |
| `token_1_2` | `1.0` | `0.7324 [0.7324, 0.7324]` | `0.8635 [0.8635, 0.8635]` | `0.0044 [0.0044, 0.0044]` | `-0.0029 [-0.0029, -0.0029]` | `0.8452 [0.8452, 0.8452]` |
| `diff_line_markers` | `0.5` | `0.8382 [0.837, 0.8388]` | `0.8634 [0.8627, 0.8638]` | `0.0043 [0.0036, 0.0047]` | `-0.003 [-0.0037, -0.0026]` | `0.8507 [0.8497, 0.8519]` |
| `diff_line_markers` | `1.0` | `0.8366 [0.8366, 0.8366]` | `0.8642 [0.8642, 0.8642]` | `0.0051 [0.0051, 0.0051]` | `-0.0022 [-0.0022, -0.0022]` | `0.8504 [0.8504, 0.8504]` |

## Interpretation

The source-router stability result is now stronger than the earlier single-view check. Character n-grams remain the strongest source identifier, but token and diff-line views still preserve a small positive end-to-end BA delta over the single matched-mixed checkpoint. This weakens the concern that the result is only a brittle character fingerprint.

The claim should still stay narrow. Group all-correct remains below the oracle source-routed system, route accuracy is source-dependent, and token routing shows that low source-classification accuracy can still preserve system BA when cross-source experts behave similarly on the affected rows. The safest wording is: learned closed-world source-aware expert selection is stable across lightweight feature views, but it is not open-set source discovery and not a universal per-source gain.

## Linked Reports

- `reports/LEARNED_CONTENT_ROUTER_STABILITY_CHAR.md`
- `reports/LEARNED_CONTENT_ROUTER_STABILITY_TOKEN.md`
- `reports/LEARNED_CONTENT_ROUTER_STABILITY.md`
