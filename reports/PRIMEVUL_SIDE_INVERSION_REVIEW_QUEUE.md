# PrimeVul Side-Inversion Review Queue

This artifact materializes the top-scored paired-window side-inversion candidates. It is meant as a review/verifier queue, not an automatic correction layer.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Top-k per seed: `5`
- Queue rows: `25`
- Unique pair keys: `16`
- True inversions: `18`
- Queue precision: `0.72`

## Per-Seed Precision

| seed | rows | true_inversions | precision |
| ---: | ---: | ---: | ---: |
| 7 | 5 | 4 | 0.8 |
| 13 | 5 | 3 | 0.6 |
| 42 | 5 | 3 | 0.6 |
| 99 | 5 | 4 | 0.8 |
| 123 | 5 | 4 | 0.8 |

## Boundary

The queue is selected from model scores and still includes gold labels for analysis. A future deployable verifier must evaluate these candidates on held-out pair groups without using gold labels.
