# PrimeVul Safe Flip Gate Failure Analysis

This report explains accepted false flips and missed true flips for a side-inversion safe flip gate.

## Summary

- Rows: `25`
- Accepted rows: `9`
- True accepts: `9`
- False accepts: `0`
- Missed true flips: `3`
- True rejects: `13`
- False-accept unique pairs: `0`

## False Accepts

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |

## Missed True Flips

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 13::2::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 1.0 |
| 13::3::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux | 26+ | -6.0 | 1 | 1.0 |
| 42::5::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 0.999866 |

## Interpretation

No false accepts were observed at this operating point; remaining risk is recall loss from missed true flips.
