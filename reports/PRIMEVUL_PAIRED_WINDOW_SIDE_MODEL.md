# PrimeVul Paired-Window Side Model

This report evaluates a dependency-free paired-window side model over the generated `A/B` contrastive examples. `Side A` is the current high-probability side, so predicting `B` means the model recommends flipping the pair orientation.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Always-A baseline accuracy: `0.8598`
- Always-A baseline balanced accuracy: `0.5`
- Eval accuracy mean: `0.7328`
- Eval balanced accuracy mean: `0.6065`
- Balanced delta vs always-A mean: `0.1065`
- Label-B recall mean: `0.4367`
- Label-B precision mean: `0.2279`
- Flipped pairs mean: `103.8`
- Accuracy delta vs always-A mean: `-0.127`
- Eval top-10 precision mean: `0.52`

## Top-K Flip Precision

| k | precision_mean | precision_min | precision_max |
| ---: | ---: | ---: | ---: |
| 1 | 0.6 | 0.0 | 1.0 |
| 3 | 0.7334 | 0.6667 | 1.0 |
| 5 | 0.72 | 0.6 | 0.8 |
| 10 | 0.52 | 0.4 | 0.7 |
| 20 | 0.35 | 0.25 | 0.5 |
| 50 | 0.26 | 0.2 | 0.32 |

## Per-Seed Results

| seed | threshold | cal_precision | cal_flipped | acc | bal_acc | label_b_recall | label_a_specificity | label_b_precision | flipped | tp | tn | fp | fn |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.1 | 1.0 | 27 | 0.6908 | 0.5576 | 0.375 | 0.7402 | 0.1842 | 114 | 21 | 265 | 93 | 35 |
| 13 | 0.4 | 1.0 | 33 | 0.785 | 0.619 | 0.4 | 0.8379 | 0.2532 | 79 | 20 | 305 | 59 | 30 |
| 42 | 0.1 | 1.0 | 32 | 0.6739 | 0.595 | 0.4902 | 0.6997 | 0.1866 | 134 | 25 | 254 | 109 | 26 |
| 99 | 0.2 | 1.0 | 31 | 0.7367 | 0.6354 | 0.5 | 0.7707 | 0.2385 | 109 | 26 | 279 | 83 | 26 |
| 123 | 0.1 | 1.0 | 28 | 0.7778 | 0.6255 | 0.4182 | 0.8329 | 0.2771 | 83 | 23 | 299 | 60 | 32 |

## Interpretation

This is a cheap signal check before any GPU model training. A useful result must beat the always-trust-high-probability baseline on held-out pair-key splits, especially on balanced accuracy and label-B recall, while any precision-controlled variant must avoid large raw-accuracy regressions. If it stays flat, the next step should be a stronger supervised contrastive model or better evidence targets rather than another hand-crafted gate.
