# PrimeVul Direction-Aware Bucket Router Calibration

This report selects the large-diff bucket threshold on a pair-key calibration split and reports the selected router on held-out pair keys.

## Protocol

- Split seed: `42`
- Calibration fraction: `0.3`
- Calibration pair groups: `263`
- Held-out eval pair groups: `614`
- Selector: `balanced_accuracy`
- Selected bucket threshold: `0.8`

## Calibration Sweep

| bucket_threshold | bal_acc | recall | specificity | precision | f1 | group_all_correct | orientation |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.5 | 0.84 | 0.8679 | 0.812 | 0.8214 | 0.844 | 0.7414 | 0.8721 |
| 0.6 | 0.8418 | 0.8642 | 0.8195 | 0.8267 | 0.845 | 0.7452 | 0.8721 |
| 0.7 | 0.8456 | 0.8642 | 0.8271 | 0.8327 | 0.8481 | 0.749 | 0.8721 |
| 0.8 | 0.8456 | 0.8604 | 0.8308 | 0.8352 | 0.8476 | 0.749 | 0.8721 |
| 0.9 | 0.8324 | 0.834 | 0.8308 | 0.8308 | 0.8324 | 0.7224 | 0.8721 |

## Held-Out Eval

This report routes large diff samples through the recall-recovery detector while keeping the baseline direction-aware detector for all other buckets.

## Routing

- Default threshold: `0.5`
- Bucket route: `26+`
- Bucket threshold: `0.8`
- Default routed rows: `1147`
- Bucket routed rows: `114`

## Overall Metrics

| metric | value |
| --- | ---: |
| num_examples | 1261 |
| presence_accuracy | 0.8136 |
| balanced_accuracy | 0.8136 |
| vulnerable_recall | 0.8159 |
| safe_specificity | 0.8114 |
| precision | 0.812 |
| f1 | 0.8139 |
| tp | 514 |
| tn | 512 |
| fp | 119 |
| fn | 116 |

## Pair/Group Metrics

| metric | value |
| --- | ---: |
| unique_pair_count | 614 |
| mixed_label_pair_count | 592 |
| group_all_correct | 438 |
| group_all_correct_rate | 0.7134 |
| orientation_eligible_pair_count | 592 |
| orientation_correct | 508 |
| orientation_accuracy | 0.8581 |

## Bucket Metrics

| bucket | n | bal_acc | recall | specificity | precision | f1 | tp | tn | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 333 | 0.7355 | 0.8144 | 0.6566 | 0.7047 | 0.7556 | 136 | 109 | 57 | 31 |
| 03-05 | 344 | 0.8606 | 0.8382 | 0.883 | 0.8788 | 0.858 | 145 | 151 | 20 | 28 |
| 06-10 | 285 | 0.8878 | 0.8921 | 0.8836 | 0.8794 | 0.8857 | 124 | 129 | 17 | 15 |
| 11-25 | 185 | 0.7789 | 0.7579 | 0.8 | 0.8 | 0.7784 | 72 | 72 | 18 | 23 |
| 26+ | 114 | 0.77 | 0.6607 | 0.8793 | 0.8409 | 0.74 | 37 | 51 | 7 | 19 |

## Same-Split Control

Baseline direction-aware detector on the same held-out pair groups:

| bal_acc | recall | specificity | precision | f1 | group_all_correct | orientation |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.8136 | 0.8143 | 0.813 | 0.813 | 0.8136 | 0.7101 | 0.8514 |
