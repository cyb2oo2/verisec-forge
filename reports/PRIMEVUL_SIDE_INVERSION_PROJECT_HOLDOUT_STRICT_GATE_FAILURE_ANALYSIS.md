# PrimeVul Safe Flip Gate Failure Analysis

This report explains accepted false flips and missed true flips for a side-inversion safe flip gate.

## Summary

- Rows: `25`
- Accepted rows: `12`
- True accepts: `9`
- False accepts: `3`
- Missed true flips: `3`
- True rejects: `10`
- False-accept unique pairs: `1`

## False Accepts

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 13::5::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat | 26+ | -6.0 | 3 | 1.0 |
| 42::1::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat | 26+ | -6.0 | 3 | 1.0 |
| 99::1::hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087 | hexchat | 26+ | -6.0 | 3 | 1.0 |

## Missed True Flips

| id | pair_key | project | bucket | evidence_score | repeat | side_score |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 13::2::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 1.0 |
| 13::3::linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283 | linux | 26+ | -6.0 | 1 | 1.0 |
| 42::5::squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784 | squid | 26+ | -18.0 | 2 | 0.999866 |

## Interpretation

False accepts are dominated by repeat-consensus errors when their evidence scores are below the evidence threshold. This suggests the consensus branch is less reliable under project-heldout candidate generation and should be tightened or conditioned on positive evidence.
