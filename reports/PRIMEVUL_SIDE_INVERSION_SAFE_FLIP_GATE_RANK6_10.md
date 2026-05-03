# PrimeVul Side-Inversion Safe Flip Gate

This report evaluates the precision-first verifier gate as a system component. It estimates what would happen if accepted review-queue candidates were used to flip pair orientation.

## Gate

- Rule: `pair_repeat_count>=3 OR evidence_score>=10`

## Summary

- Candidate rows / unique pairs: `25` / `23`
- Candidate true-flip rows / pairs: `8` / `8`
- Accepted rows / unique pairs: `2` / `2`
- Repaired side-error rows / pairs: `2` / `2`
- Introduced side-error rows / pairs: `0` / `0`
- Missed true-flip rows / pairs: `6` / `6`
- Accept precision / recall: `1.0` / `0.25`
- Net row / pair gain if applied: `2` / `2`

## Accepted Candidates

| id | pair_repeat | evidence_score | true_flip | project | bucket |
| --- | ---: | ---: | --- | --- | --- |
| 99::8::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 1 | 13.0 | True | linux-2.6 | 06-10 |
| 123::6::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 1 | 29.0 | True | drogon | 11-25 |

## Boundary

This is still an offline gate over a gold-labeled review queue selected from current model failures. It should be used to define a safety target and candidate operating point, not as proof of a deployable automatic correction system.
