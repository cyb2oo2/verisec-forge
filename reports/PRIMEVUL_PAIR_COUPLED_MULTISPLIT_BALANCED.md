# PrimeVul Pair-Coupled Multi-Split Analysis

This report repeats calibration/evaluation over multiple pair-key split seeds. Each seed independently selects the bucket threshold and pair-coupling margin on its calibration pair groups, then reports on held-out pair groups.

Selection policy:

- bucket threshold primary metric: `balanced_accuracy`
- bucket threshold tie-break: `highest_bucket_threshold`
- pair-coupling margin primary metric: `balanced_accuracy`
- pair-coupling margin tie-break: `lowest_margin`
- selection scores are recomputed from raw counts before rounding report tables

## Summary

| metric | mean | stdev | min | max |
| --- | ---: | ---: | ---: | ---: |
| baseline_balanced_accuracy | 0.822 | 0.0082 | 0.8136 | 0.8311 |
| bucket_balanced_accuracy | 0.8224 | 0.0072 | 0.8136 | 0.8312 |
| pair_balanced_accuracy | 0.8572 | 0.0061 | 0.8493 | 0.8644 |
| bucket_group_all_correct | 0.7225 | 0.0105 | 0.7117 | 0.7394 |
| pair_group_all_correct | 0.8339 | 0.0124 | 0.8208 | 0.8502 |
| pair_minus_bucket_balanced_accuracy | 0.0348 | 0.0025 | 0.0317 | 0.0384 |
| pair_minus_bucket_group_all_correct | 0.1114 | 0.01 | 0.101 | 0.1271 |

## Per-Seed Results

| seed | bucket_th | margin | baseline_bal | bucket_bal | pair_bal | bucket_group | pair_group | pair-bucket bal | pair-bucket group | McNemar p | group sign p |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.7 | 0.02 | 0.8157 | 0.818 | 0.8528 | 0.7166 | 0.8225 | 0.0348 | 0.1059 | 1.6e-05 | 1e-06 |
| 13 | 0.8 | 0.02 | 0.8304 | 0.8312 | 0.8644 | 0.7394 | 0.8404 | 0.0332 | 0.101 | 2.1e-05 | 1e-06 |
| 42 | 0.7 | 0.02 | 0.8136 | 0.8136 | 0.8493 | 0.7117 | 0.8208 | 0.0357 | 0.1091 | 1.6e-05 | 1e-06 |
| 99 | 0.8 | 0.02 | 0.8191 | 0.8215 | 0.8599 | 0.7215 | 0.8355 | 0.0384 | 0.114 | 3e-06 | 1e-06 |
| 123 | 0.6 | 0.0 | 0.8311 | 0.8279 | 0.8596 | 0.7231 | 0.8502 | 0.0317 | 0.1271 | 0.001269 | 1e-06 |

## Interpretation

This is the reviewer-facing stability check. Pair-coupled decoding should be described as credible only if the pair-coupled deltas remain positive across split seeds and paired tests are consistently favorable.
