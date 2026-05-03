# PrimeVul Side-Inversion Review Queue

This artifact materializes the top-scored paired-window side-inversion candidates. It is meant as a review/verifier queue, not an automatic correction layer.

## Summary

- Seeds: `[211, 307, 401, 503, 601]`
- Split field: `pair_key_random`
- Rank window per seed: `1-5`
- Queue rows: `25`
- Unique pair keys: `18`
- True inversions: `13`
- Queue precision: `0.52`

## Per-Seed Precision

| seed | rows | true_inversions | precision |
| ---: | ---: | ---: | ---: |
| 211 | 5 | 1 | 0.2 |
| 307 | 5 | 3 | 0.6 |
| 401 | 5 | 2 | 0.4 |
| 503 | 5 | 4 | 0.8 |
| 601 | 5 | 3 | 0.6 |

## Boundary

The queue is selected from model scores and still includes gold labels for analysis. A future deployable verifier must evaluate these candidates on held-out pair groups without using gold labels.
