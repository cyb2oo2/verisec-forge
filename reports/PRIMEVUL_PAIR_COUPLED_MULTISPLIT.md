# PrimeVul Pair-Coupled Multi-Split Analysis

This report repeats calibration/evaluation over multiple pair-key split seeds. Each seed independently selects the bucket threshold and pair-coupling margin on its calibration pair groups, then reports on held-out pair groups.

## Summary

| metric | mean | stdev | min | max |
| --- | ---: | ---: | ---: | ---: |
| baseline_balanced_accuracy | 0.822 | 0.0082 | 0.8136 | 0.8311 |
| bucket_balanced_accuracy | 0.8224 | 0.0072 | 0.8136 | 0.8312 |
| pair_balanced_accuracy | 0.8512 | 0.0076 | 0.8426 | 0.8596 |
| bucket_group_all_correct | 0.7228 | 0.0101 | 0.7134 | 0.7394 |
| pair_group_all_correct | 0.842 | 0.0076 | 0.8339 | 0.8502 |
| pair_minus_bucket_balanced_accuracy | 0.0288 | 0.0048 | 0.023 | 0.0344 |
| pair_minus_bucket_group_all_correct | 0.1192 | 0.0075 | 0.1075 | 0.1271 |

## Per-Seed Results

| seed | bucket_th | margin | baseline_bal | bucket_bal | pair_bal | bucket_group | pair_group | pair-bucket bal | pair-bucket group | McNemar p | group sign p |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.7 | 0.0 | 0.8157 | 0.818 | 0.8426 | 0.7166 | 0.8339 | 0.0246 | 0.1173 | 0.01185 | 1e-06 |
| 13 | 0.8 | 0.0 | 0.8304 | 0.8312 | 0.8542 | 0.7394 | 0.8469 | 0.023 | 0.1075 | 0.015644 | 1e-06 |
| 42 | 0.8 | 0.0 | 0.8136 | 0.8136 | 0.8438 | 0.7134 | 0.8339 | 0.0302 | 0.1205 | 0.001668 | 1e-06 |
| 99 | 0.8 | 0.0 | 0.8191 | 0.8215 | 0.8559 | 0.7215 | 0.8453 | 0.0344 | 0.1238 | 0.0003 | 1e-06 |
| 123 | 0.6 | 0.0 | 0.8311 | 0.8279 | 0.8596 | 0.7231 | 0.8502 | 0.0317 | 0.1271 | 0.001269 | 1e-06 |

## Interpretation

This is the reviewer-facing stability check. Pair-coupled decoding should be described as credible only if the pair-coupled deltas remain positive across split seeds and paired tests are consistently favorable.
