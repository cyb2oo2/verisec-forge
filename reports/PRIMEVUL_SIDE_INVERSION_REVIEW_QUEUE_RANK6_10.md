# PrimeVul Side-Inversion Review Queue

This artifact materializes the top-scored paired-window side-inversion candidates. It is meant as a review/verifier queue, not an automatic correction layer.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Rank window per seed: `6-10`
- Queue rows: `25`
- Unique pair keys: `23`
- True inversions: `8`
- Queue precision: `0.32`

## Per-Seed Precision

| seed | rows | true_inversions | precision |
| ---: | ---: | ---: | ---: |
| 7 | 5 | 1 | 0.2 |
| 13 | 5 | 1 | 0.2 |
| 42 | 5 | 1 | 0.2 |
| 99 | 5 | 3 | 0.6 |
| 123 | 5 | 2 | 0.4 |

## Boundary

The queue is selected from model scores and still includes gold labels for analysis. A future deployable verifier must evaluate these candidates on held-out pair groups without using gold labels.
