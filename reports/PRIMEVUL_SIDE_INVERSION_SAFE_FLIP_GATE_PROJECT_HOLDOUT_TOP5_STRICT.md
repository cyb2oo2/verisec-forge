# PrimeVul Side-Inversion Safe Flip Gate

This report evaluates the precision-first verifier gate as a system component. It estimates what would happen if accepted review-queue candidates were used to flip pair orientation.

## Gate

- Rule: `pair_repeat_count>=3 OR evidence_score>=13`

## Summary

- Candidate rows / unique pairs: `25` / `16`
- Candidate true-flip rows / pairs: `12` / `6`
- Accepted rows / unique pairs: `12` / `5`
- Repaired side-error rows / pairs: `9` / `4`
- Introduced side-error rows / pairs: `3` / `1`
- Missed true-flip rows / pairs: `3` / `2`
- Accept precision / recall: `0.75` / `0.75`
- Net row / pair gain if applied: `6` / `3`

## Accepted Candidates

| id | pair_repeat | evidence_score | true_flip | project | bucket |
| --- | ---: | ---: | --- | --- | --- |
| 7::1::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 2 | 29.0 | True | drogon | 11-25 |
| 7::3::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |
| 7::4::linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787 | 1 | 13.0 | True | linux-2.6 | 06-10 |
| 13::1::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 13::5::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | 3 | -6.0 | False | hexchat | 26+ |
| 42::1::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | 3 | -6.0 | False | hexchat | 26+ |
| 42::2::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |
| 99::1::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | 3 | -6.0 | False | hexchat | 26+ |
| 99::2::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 99::3::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | 3 | 10.0 | True | tensorflow | 11-25 |
| 123::1::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | 3 | 11.0 | True | gpac | 11-25 |
| 123::3::drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297 | 2 | 29.0 | True | drogon | 11-25 |

## Boundary

This is still an offline gate over a gold-labeled review queue selected from current model failures. It should be used to define a safety target and candidate operating point, not as proof of a deployable automatic correction system.
