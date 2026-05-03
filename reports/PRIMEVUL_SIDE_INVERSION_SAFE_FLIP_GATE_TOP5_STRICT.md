# PrimeVul Side-Inversion Safe Flip Gate

This report evaluates the precision-first verifier gate as a system component. It estimates what would happen if accepted review-queue candidates were used to flip pair orientation.

## Gate

- Rule: `pair_repeat_count>=3 OR evidence_score>=13`

## Summary

- Candidate rows / unique pairs: `25` / `16`
- Candidate true-flip rows / pairs: `18` / `10`
- Accepted rows / unique pairs: `10` / `4`
- Repaired side-error rows / pairs: `10` / `4`
- Introduced side-error rows / pairs: `0` / `0`
- Missed true-flip rows / pairs: `8` / `6`
- Accept precision / recall: `1.0` / `0.5556`
- Net row / pair gain if applied: `10` / `4`

## Accepted Candidates

| id | pair_repeat | evidence_score | true_flip | project | bucket |
| --- | ---: | ---: | --- | --- | --- |
| 7::1::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 1 | 29.0 | True | drogon | 11-25 |
| 7::3::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 3 | 13.0 | True | linux-2.6 | 06-10 |
| 13::2::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 13::4::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 3 | 13.0 | True | linux-2.6 | 06-10 |
| 42::2::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | 3 | -6.0 | True | linux | 26+ |
| 42::5::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 3 | 13.0 | True | linux-2.6 | 06-10 |
| 99::1::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | 3 | -6.0 | True | linux | 26+ |
| 99::4::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 123::1::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | 3 | -6.0 | True | linux | 26+ |
| 123::2::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |

## Boundary

This is still an offline gate over a gold-labeled review queue selected from current model failures. It should be used to define a safety target and candidate operating point, not as proof of a deployable automatic correction system.
