# PrimeVul Candidate Recall Analysis

This report compares hunk candidate-generation strategies using the same heuristic pseudo labels. It estimates whether the evidence-localization bottleneck is candidate recall or only candidate scoring.

## Strategy Summary

| strategy | candidate_rows | source_rows | positive_rate | top1 | top3 | top8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hunk | 4697 | 2999 | 0.4788 | 0.5575 | 0.5802 | 0.5822 |
| line_window | 13538 | 2999 | 0.4799 | 0.4978 | 0.6559 | 0.7046 |
| hunk_plus_window | 15914 | 2999 | 0.4981 | 0.5575 | 0.6589 | 0.7082 |

## Top-K Details

### hunk

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5575 | 0.5627 | 0.5524 | 1672 | 2999 |
| 2 | 0.5799 | 0.5813 | 0.5784 | 1739 | 2999 |
| 3 | 0.5802 | 0.5813 | 0.5791 | 1740 | 2999 |
| 5 | 0.5815 | 0.5833 | 0.5797 | 1744 | 2999 |
| 8 | 0.5822 | 0.584 | 0.5804 | 1746 | 2999 |

### line_window

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.4978 | 0.498 | 0.4977 | 1493 | 2999 |
| 2 | 0.6052 | 0.6067 | 0.6037 | 1815 | 2999 |
| 3 | 0.6559 | 0.6567 | 0.6551 | 1967 | 2999 |
| 5 | 0.6922 | 0.6913 | 0.6931 | 2076 | 2999 |
| 8 | 0.7046 | 0.7087 | 0.7005 | 2113 | 2999 |

### hunk_plus_window

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5575 | 0.5627 | 0.5524 | 1672 | 2999 |
| 2 | 0.6155 | 0.614 | 0.6171 | 1846 | 2999 |
| 3 | 0.6589 | 0.6573 | 0.6604 | 1976 | 2999 |
| 5 | 0.6956 | 0.6947 | 0.6965 | 2086 | 2999 |
| 8 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
