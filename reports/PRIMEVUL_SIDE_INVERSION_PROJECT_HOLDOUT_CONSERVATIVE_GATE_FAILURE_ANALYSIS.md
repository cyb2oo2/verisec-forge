# PrimeVul Safe Flip Gate Failure Analysis

This report explains accepted false flips and missed true flips for a side-inversion safe flip gate.

## Summary

- Rows: `25`
- Accepted rows: `3`
- True accepts: `3`
- False accepts: `0`
- Missed true flips: `9`
- True rejects: `13`
- False-accept unique pairs: `0`

## False Accepts

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |

## Missed True Flips

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 7::3::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow | 11-25 | 10.0 | 3 | 0.99995 |
| 13::1::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac | 11-25 | 11.0 | 3 | 1.0 |
| 13::2::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 1.0 |
| 13::3::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux | 26+ | -6.0 | 1 | 1.0 |
| 42::2::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow | 11-25 | 10.0 | 3 | 1.0 |
| 42::5::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 0.999866 |
| 99::2::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac | 11-25 | 11.0 | 3 | 1.0 |
| 99::3::tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614 | tensorflow | 11-25 | 10.0 | 3 | 1.0 |
| 123::1::gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441 | gpac | 11-25 | 11.0 | 3 | 1.0 |

## Interpretation

No false accepts were observed at this operating point; remaining risk is recall loss from missed true flips.
