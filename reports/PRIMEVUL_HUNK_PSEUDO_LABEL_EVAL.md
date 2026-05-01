# PrimeVul Hunk Pseudo-Label Dataset

This report builds hunk-level pseudo labels from direction-aware support heuristics. It is a bootstrapping artifact for training or evaluating a learned hunk scorer, not human evidence-span ground truth.

## Summary

- Hunk rows: `2536`
- Source rows: `1787`
- Pair groups: `877`
- Positive hunk rate: `0.5335`

## Top-K Coverage

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5792 | 0.5743 | 0.5841 | 1035 | 1787 |
| 2 | 0.6066 | 0.6 | 0.6132 | 1084 | 1787 |
| 3 | 0.6128 | 0.6067 | 0.6188 | 1095 | 1787 |
| 5 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| 8 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |

## Aggregate Signals

- Top direction labels: `[('direction_unclear', 868), ('candidate_adds_protection', 807), ('candidate_removes_protection', 785), ('candidate_introduces_risk', 143), ('candidate_removes_risk', 142)]`
- Top CWEs: `[('cwe-787', 414), ('cwe-125', 302), ('cwe-703', 228), ('cwe-476', 219), ('cwe-416', 170), ('cwe-369', 106), ('cwe-20', 82), ('cwe-200', 80), ('cwe-120', 76), ('cwe-190', 75)]`
