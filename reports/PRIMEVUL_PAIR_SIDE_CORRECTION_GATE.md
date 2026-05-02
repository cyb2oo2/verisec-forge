# PrimeVul Pair-Side Correction Gate

This report trains a lightweight gate on calibration pair groups to detect likely side inversions. If a held-out pair group is gated, the system falls back from pair-coupled labels to the pre-coupled predictions. It is a correction-layer diagnostic, not a new model checkpoint.

## Protocol

- Calibration pair groups: `184`
- Held-out eval pair groups: `430`
- Selector: `balanced_accuracy`
- Selected gate threshold: `0.7`
- Held-out gated groups: `6`

## Held-Out Eval

| system | bal_acc | recall | specificity | f1 | group_all_correct | orientation | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pair_coupled | 0.847 | 0.8472 | 0.8468 | 0.8472 | 0.814 | 0.8575 | 68 | 68 |
| correction_gate | 0.8481 | 0.8472 | 0.8491 | 0.8481 | 0.814 | 0.8575 | 67 | 68 |

## Calibration Sweep

| threshold | bal_acc | group_all_correct | gated_groups |
| ---: | ---: | ---: | ---: |
| 0.1 | 0.8386 | 0.7663 | 63 |
| 0.2 | 0.8358 | 0.7717 | 39 |
| 0.3 | 0.8466 | 0.7989 | 23 |
| 0.4 | 0.8494 | 0.8152 | 13 |
| 0.5 | 0.8521 | 0.8261 | 9 |
| 0.6 | 0.8494 | 0.8261 | 5 |
| 0.7 | 0.8548 | 0.837 | 1 |
| 0.8 | 0.8548 | 0.837 | 0 |
| 0.9 | 0.8548 | 0.837 | 0 |

## Learned Weights

- `gap_squared`: `-1.467288`
- `mean_probability`: `-1.427114`
- `top_probability`: `-1.396709`
- `bias`: `1.350347`
- `top_bucket_11_25`: `1.297185`
- `probability_distance_from_half`: `-1.059612`
- `gap`: `-0.706295`
- `second_probability`: `-0.690414`
- `top_bucket_00_02`: `-0.604182`
- `changed_lines_max_log`: `-0.444641`
- `top_bucket_06_10`: `0.379058`
- `same_bucket`: `0.293189`
- `top_bucket_26plus`: `0.254116`
- `changed_lines_min_log`: `0.167927`
- `top_bucket_03_05`: `0.02417`

## Interpretation

A positive held-out gain would support a separate pair-side correction layer. A flat or negative result means the confident inversion set is still valuable for diagnosis, but its signal is not yet captured by these cheap metadata/probability features.
