# PrimeVul Direction-Aware Bucket Router

This report routes large diff samples through the recall-recovery detector while keeping the baseline direction-aware detector for all other buckets.

## Routing

- Default threshold: `0.5`
- Bucket route: `26+`
- Bucket threshold: `0.8`
- Default routed rows: `1633`
- Bucket routed rows: `159`

## Overall Metrics

| metric | value |
| --- | ---: |
| num_examples | 1792 |
| presence_accuracy | 0.8231 |
| balanced_accuracy | 0.8231 |
| vulnerable_recall | 0.8291 |
| safe_specificity | 0.8172 |
| precision | 0.819 |
| f1 | 0.824 |
| tp | 742 |
| tn | 733 |
| fp | 164 |
| fn | 153 |

## Pair/Group Metrics

| metric | value |
| --- | ---: |
| unique_pair_count | 877 |
| mixed_label_pair_count | 850 |
| group_all_correct | 635 |
| group_all_correct_rate | 0.7241 |
| orientation_eligible_pair_count | 850 |
| orientation_correct | 733 |
| orientation_accuracy | 0.8624 |

## Bucket Metrics

| bucket | n | bal_acc | recall | specificity | precision | f1 | tp | tn | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 489 | 0.75 | 0.8333 | 0.6667 | 0.7168 | 0.7707 | 205 | 162 | 81 | 41 |
| 03-05 | 483 | 0.8613 | 0.8471 | 0.8755 | 0.8723 | 0.8595 | 205 | 211 | 30 | 37 |
| 06-10 | 386 | 0.8888 | 0.9 | 0.8776 | 0.8769 | 0.8883 | 171 | 172 | 24 | 19 |
| 11-25 | 275 | 0.815 | 0.777 | 0.8529 | 0.8438 | 0.809 | 108 | 116 | 20 | 31 |
| 26+ | 159 | 0.7842 | 0.6795 | 0.8889 | 0.8548 | 0.7571 | 53 | 72 | 9 | 25 |
