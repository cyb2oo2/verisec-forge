# PrimeVul Side-Inversion Safe Flip Gate

This report evaluates the precision-first verifier gate as a system component. It estimates what would happen if accepted review-queue candidates were used to flip pair orientation.

## Gate

- Rule: `pair_repeat_count>=3 OR evidence_score>=13`

## Summary

- Candidate rows / unique pairs: `25` / `18`
- Candidate true-flip rows / pairs: `13` / `7`
- Accepted rows / unique pairs: `9` / `4`
- Repaired side-error rows / pairs: `9` / `4`
- Introduced side-error rows / pairs: `0` / `0`
- Missed true-flip rows / pairs: `4` / `3`
- Accept precision / recall: `1.0` / `0.6923`
- Net row / pair gain if applied: `9` / `4`

## Accepted Candidates

| id | pair_repeat | evidence_score | true_flip | project | bucket |
| --- | ---: | ---: | --- | --- | --- |
| 307::1::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 2 | 29.0 | True | drogon | 11-25 |
| 307::3::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |
| 307::5::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 1 | 13.0 | True | linux-2.6 | 06-10 |
| 401::1::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 503::2::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 503::4::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |
| 601::2::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 2 | 29.0 | True | drogon | 11-25 |
| 601::3::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 601::4::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |

## Boundary

This is still an offline gate over a gold-labeled review queue selected from current model failures. It should be used to define a safety target and candidate operating point, not as proof of a deployable automatic correction system.
