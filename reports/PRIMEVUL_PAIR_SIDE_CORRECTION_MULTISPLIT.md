# PrimeVul Pair-Side Correction Multi-Split

This report repeats the lightweight pair-side correction gate across pair-key calibration/eval splits. It checks whether the correction signal is stable enough to justify a training follow-up.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Balanced accuracy delta mean: `-0.0`
- Balanced accuracy delta range: `-0.0012` to `0.0011`
- Group all-correct delta mean: `-0.0019`
- Gated groups mean: `6.8`

## Per-Seed Results

| seed | threshold | base_bal | corr_bal | bal_delta | base_group | corr_group | group_delta | gated_groups | fp_delta | fn_delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.8 | 0.8544 | 0.8544 | 0.0 | 0.8233 | 0.8233 | 0.0 | 8 | 0 | 0 |
| 13 | 0.7 | 0.8455 | 0.8455 | 0.0 | 0.8163 | 0.814 | -0.0023 | 10 | -1 | 1 |
| 42 | 0.7 | 0.847 | 0.8481 | 0.0011 | 0.814 | 0.814 | 0.0 | 6 | -1 | 0 |
| 99 | 0.7 | 0.8441 | 0.8441 | 0.0 | 0.814 | 0.8093 | -0.0047 | 7 | -2 | 2 |
| 123 | 0.4 | 0.8381 | 0.8369 | -0.0012 | 0.807 | 0.8047 | -0.0023 | 3 | 0 | 1 |

## Interpretation

If deltas are not consistently positive, the current cheap gate should be treated as a diagnostic baseline rather than a deployable correction layer. The confident inversion set remains useful, but stronger features or an explicit contrastive model are needed.
