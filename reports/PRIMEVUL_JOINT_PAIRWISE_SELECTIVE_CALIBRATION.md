# Learned Joint Pairwise Selective Calibration

This analysis preserves the pair-head direction rule and calibrates only confidence and abstention. A non-zero direction threshold is intentionally not tuned because the stored prediction rows are gold-aligned by class; tuning that threshold would leak target ordering.

## Protocol

- pair-key split seeds: `7,13,42,99,123`
- calibration fraction: `0.3`
- minimum calibration coverage: `0.8`
- margin selection: highest calibration accepted accuracy subject to minimum coverage
- temperature selection: lowest calibration correctness NLL
- held-out reporting: coverage, accepted accuracy, error capture, NLL, Brier, and ECE

## Multi-Split Summary

| metric | mean | stdev | min | max |
| --- | ---: | ---: | ---: | ---: |
| baseline_accuracy | 0.8352 | 0.0072 | 0.8273 | 0.8446 |
| selective_coverage | 0.7896 | 0.0065 | 0.7789 | 0.7962 |
| selective_accuracy | 0.8767 | 0.0056 | 0.8709 | 0.8847 |
| selective_error_capture_rate | 0.4087 | 0.0214 | 0.3889 | 0.4409 |
| raw_nll | 0.4629 | 0.0083 | 0.4503 | 0.4735 |
| calibrated_nll | 0.4236 | 0.0034 | 0.4210 | 0.4295 |
| raw_brier | 0.1353 | 0.0018 | 0.1334 | 0.1376 |
| calibrated_brier | 0.1354 | 0.0013 | 0.1344 | 0.1375 |
| raw_ece_10 | 0.1017 | 0.0060 | 0.0912 | 0.1063 |
| calibrated_ece_10 | 0.0780 | 0.0112 | 0.0675 | 0.0934 |

## Per-Split Results

| seed | temperature | margin | baseline acc | coverage | accepted acc | error capture | raw ECE | calibrated ECE |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 2.0 | 0.075 | 0.8290 | 0.7910 | 0.8734 | 0.4141 | 0.1021 | 0.0675 |
| 13 | 2.0 | 0.075 | 0.8446 | 0.7927 | 0.8802 | 0.3889 | 0.1063 | 0.0860 |
| 42 | 2.0 | 0.075 | 0.8359 | 0.7962 | 0.8742 | 0.3895 | 0.1037 | 0.0739 |
| 99 | 2.0 | 0.075 | 0.8394 | 0.7789 | 0.8847 | 0.4409 | 0.1049 | 0.0934 |
| 123 | 2.0 | 0.075 | 0.8273 | 0.7893 | 0.8709 | 0.4100 | 0.0912 | 0.0692 |

## Claim Boundary

Selective accuracy is conditional on abstaining from low-margin pairs and is not a replacement for full-coverage orientation accuracy. Temperature scaling changes confidence calibration only; it does not change pair decisions.
