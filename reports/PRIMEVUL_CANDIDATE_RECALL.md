# PrimeVul Candidate Recall Analysis

This report compares hunk candidate-generation strategies using the same heuristic pseudo labels. It estimates whether the evidence-localization bottleneck is candidate recall or only candidate scoring.

## Strategy Summary

| strategy | candidate_rows | source_rows | positive_rate | top1 | top3 | top8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hunk | 2536 | 1787 | 0.5335 | 0.5792 | 0.6128 | 0.615 |
| line_window | 7685 | 1785 | 0.504 | 0.5171 | 0.6622 | 0.707 |
| hunk_plus_window | 9160 | 1787 | 0.5222 | 0.5792 | 0.6676 | 0.7073 |

## Top-K Details

### hunk

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5792 | 0.5743 | 0.5841 | 1035 | 1787 |
| 2 | 0.6066 | 0.6 | 0.6132 | 1084 | 1787 |
| 3 | 0.6128 | 0.6067 | 0.6188 | 1095 | 1787 |
| 5 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| 8 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |

### line_window

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5171 | 0.5101 | 0.5241 | 923 | 1785 |
| 2 | 0.6224 | 0.6174 | 0.6274 | 1111 | 1785 |
| 3 | 0.6622 | 0.6588 | 0.6655 | 1182 | 1785 |
| 5 | 0.698 | 0.6957 | 0.7003 | 1246 | 1785 |
| 8 | 0.707 | 0.7047 | 0.7093 | 1262 | 1785 |

### hunk_plus_window

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5792 | 0.5743 | 0.5841 | 1035 | 1787 |
| 2 | 0.6279 | 0.6257 | 0.63 | 1122 | 1787 |
| 3 | 0.6676 | 0.6626 | 0.6726 | 1193 | 1787 |
| 5 | 0.6961 | 0.6939 | 0.6984 | 1244 | 1787 |
| 8 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
