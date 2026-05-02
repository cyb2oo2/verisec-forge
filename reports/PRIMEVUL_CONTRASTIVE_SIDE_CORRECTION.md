# PrimeVul Contrastive Side-Correction

This report augments the shallow pair-side correction gate with contrastive hunk/window features from the high-probability and low-probability sides of each pair. It checks whether pseudo-evidence signals are enough to correct confident side inversions.

## Summary

- Seeds: `[7, 13, 42, 99, 123]`
- Balanced accuracy delta mean: `-0.0002`
- Balanced accuracy delta range: `-0.0023` to `0.0034`
- Group all-correct delta mean: `-0.0047`
- Gated groups mean: `28.2`

## Per-Seed Results

| seed | threshold | base_bal | corr_bal | bal_delta | base_group | corr_group | group_delta | gated_groups | fp_delta | fn_delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.8 | 0.8544 | 0.8522 | -0.0022 | 0.8233 | 0.8186 | -0.0047 | 30 | 1 | 1 |
| 13 | 0.9 | 0.8455 | 0.8455 | 0.0 | 0.8163 | 0.8116 | -0.0047 | 21 | 1 | -1 |
| 42 | 0.6 | 0.847 | 0.8504 | 0.0034 | 0.814 | 0.8163 | 0.0023 | 16 | -1 | -2 |
| 99 | 0.9 | 0.8441 | 0.8441 | 0.0 | 0.814 | 0.807 | -0.007 | 46 | -2 | 2 |
| 123 | 0.6 | 0.8381 | 0.8358 | -0.0023 | 0.807 | 0.7977 | -0.0093 | 28 | 0 | 2 |

## Interpretation

If this remains flat, then pseudo-evidence aggregates are still too weak for a reliable correction layer. The next step should be explicit contrastive model training on paired windows, not more hand-built gate features.
