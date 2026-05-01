# PrimeVul Hunk Pseudo-Label Dataset

This report builds hunk-level pseudo labels from direction-aware support heuristics. It is a bootstrapping artifact for training or evaluating a learned hunk scorer, not human evidence-span ground truth.

## Summary

- Hunk rows: `4697`
- Source rows: `2999`
- Pair groups: `2269`
- Positive hunk rate: `0.4788`

## Top-K Coverage

| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.5575 | 0.5627 | 0.5524 | 1672 | 2999 |
| 2 | 0.5799 | 0.5813 | 0.5784 | 1739 | 2999 |
| 3 | 0.5802 | 0.5813 | 0.5791 | 1740 | 2999 |
| 5 | 0.5815 | 0.5833 | 0.5797 | 1744 | 2999 |
| 8 | 0.5822 | 0.584 | 0.5804 | 1746 | 2999 |

## Aggregate Signals

- Top direction labels: `[('direction_unclear', 1814), ('candidate_adds_protection', 1424), ('candidate_removes_protection', 1373), ('candidate_introduces_risk', 217), ('candidate_removes_risk', 207)]`
- Top CWEs: `[('cwe-119', 698), ('cwe-125', 607), ('cwe-20', 435), ('cwe-787', 314), ('cwe-476', 248), ('cwe-200', 243), ('cwe-416', 233), ('cwe-190', 170), ('cwe-399', 163), ('cwe-189', 152)]`
