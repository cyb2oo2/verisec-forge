# PrimeVul Pair-Coupled Router

This report applies pair-level decoding on top of the validation-selected bucket router. Eligible pair groups are forced to assign the higher-probability side as vulnerable and the lower-probability side as safe when the probability gap exceeds the selected margin.

## Protocol

- Calibration pair groups: `263`
- Held-out eval pair groups: `614`
- Selector: `balanced_accuracy`
- Selected margin: `0.02`
- Tie-break policy: `lowest_margin`
- Selection score (unrounded): `balanced_accuracy=0.879493545183714`

## Calibration Sweep

| margin | bal_acc | recall | specificity | f1 | group_all_correct | orientation | coupled_groups |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.0 | 0.8663 | 0.8566 | 0.8759 | 0.8648 | 0.8593 | 0.8721 | 258 |
| 0.02 | 0.8795 | 0.8906 | 0.8684 | 0.8806 | 0.8555 | 0.8721 | 239 |
| 0.05 | 0.8757 | 0.8906 | 0.8609 | 0.8773 | 0.8327 | 0.8721 | 229 |
| 0.1 | 0.8607 | 0.8906 | 0.8308 | 0.8645 | 0.7947 | 0.8721 | 216 |
| 0.2 | 0.8513 | 0.8717 | 0.8308 | 0.854 | 0.7643 | 0.8721 | 201 |

## Held-Out Eval

This report routes large diff samples through the recall-recovery detector while keeping the baseline direction-aware detector for all other buckets.

## Routing

- Default threshold: `0.5`
- Bucket route: `26+`
- Bucket threshold: `0.7`
- Default routed rows: `1147`
- Bucket routed rows: `114`

## Overall Metrics

| metric | value |
| --- | ---: |
| num_examples | 1261 |
| presence_accuracy | 0.8493 |
| balanced_accuracy | 0.8493 |
| vulnerable_recall | 0.8492 |
| safe_specificity | 0.8494 |
| precision | 0.8492 |
| f1 | 0.8492 |
| tp | 535 |
| tn | 536 |
| fp | 95 |
| fn | 95 |

## Pair/Group Metrics

| metric | value |
| --- | ---: |
| unique_pair_count | 614 |
| mixed_label_pair_count | 592 |
| group_all_correct | 504 |
| group_all_correct_rate | 0.8208 |
| orientation_eligible_pair_count | 592 |
| orientation_correct | 508 |
| orientation_accuracy | 0.8581 |

## Bucket Metrics

| bucket | n | bal_acc | recall | specificity | precision | f1 | tp | tn | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 333 | 0.8228 | 0.8443 | 0.8012 | 0.8103 | 0.827 | 141 | 133 | 33 | 26 |
| 03-05 | 344 | 0.8692 | 0.8613 | 0.8772 | 0.8765 | 0.8688 | 149 | 150 | 21 | 24 |
| 06-10 | 285 | 0.9051 | 0.8993 | 0.911 | 0.9058 | 0.9025 | 125 | 133 | 13 | 14 |
| 11-25 | 185 | 0.7947 | 0.7895 | 0.8 | 0.8065 | 0.7979 | 75 | 72 | 18 | 20 |
| 26+ | 114 | 0.8156 | 0.8036 | 0.8276 | 0.8182 | 0.8108 | 45 | 48 | 10 | 11 |

## Same-Split Control

| system | bal_acc | recall | specificity | f1 | group_all_correct | orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline_direction_aware | 0.8136 | 0.8143 | 0.813 | 0.8136 | 0.7101 | 0.8514 |
| bucket_router | 0.8136 | 0.8222 | 0.8051 | 0.8151 | 0.7117 | 0.8581 |
