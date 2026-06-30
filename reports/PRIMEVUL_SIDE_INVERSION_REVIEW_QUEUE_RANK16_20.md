# PrimeVul Side-Inversion Review Queue

This artifact materializes the top-scored paired-window side-inversion candidates. It is meant as a review/verifier queue, not an automatic correction layer.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Split field: `pair_key_random`
- Rank window per seed: `16-20`
- Queue rows: `25`
- Unique pair keys: `25`
- True inversions: `5`
- Queue precision: `0.2`

## Per-Seed Precision

| seed | rows | true_inversions | precision |
| ---: | ---: | ---: | ---: |
| 7 | 5 | 0 | 0.0 |
| 13 | 5 | 1 | 0.2 |
| 42 | 5 | 0 | 0.0 |
| 99 | 5 | 3 | 0.6 |
| 123 | 5 | 1 | 0.2 |

## Boundary

The queue is selected from model scores and still includes gold labels for analysis. A future deployable verifier must evaluate these candidates on held-out pair groups without using gold labels.
