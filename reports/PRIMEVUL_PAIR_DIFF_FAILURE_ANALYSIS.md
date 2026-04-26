# PrimeVul Paired Diff Failure Analysis

This report is generated from the diff-only paired eval predictions by `scripts/analyze_primevul_diff_failures.py`.

## Summary

- Threshold: `0.6000`
- Accuracy: `0.8158`
- Recall: `0.8022`
- Specificity: `0.8294`
- Precision: `0.8243`
- Errors: `153` false positives and `177` false negatives out of `1792` examples
- Pair groups: `877` unique groups
- Group all-correct rate: `0.6978`
- Orientation accuracy: `0.8424`

## By CWE

| vulnerability_type | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cwe-787 | 296 | 50 | 0.1689 | 22 | 28 | 121 | 125 |
| cwe-125 | 214 | 34 | 0.1589 | 16 | 18 | 88 | 92 |
| cwe-703 | 158 | 26 | 0.1646 | 14 | 12 | 67 | 65 |
| cwe-416 | 105 | 24 | 0.2286 | 10 | 14 | 40 | 41 |
| cwe-476 | 164 | 21 | 0.1280 | 8 | 13 | 69 | 74 |
| cwe-190 | 61 | 14 | 0.2295 | 6 | 8 | 23 | 24 |
| cwe-200 | 59 | 13 | 0.2203 | 6 | 7 | 22 | 24 |
| cwe-119 | 52 | 11 | 0.2115 | 6 | 5 | 19 | 22 |
| cwe-415 | 32 | 10 | 0.3125 | 4 | 6 | 10 | 12 |
| cwe-20 | 48 | 8 | 0.1667 | 4 | 4 | 20 | 20 |
| cwe-835 | 24 | 8 | 0.3333 | 3 | 5 | 7 | 9 |
| cwe-120 | 38 | 7 | 0.1842 | 3 | 4 | 15 | 16 |

## By Project

| project | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| linux | 256 | 50 | 0.1953 | 27 | 23 | 105 | 101 |
| tensorflow | 260 | 25 | 0.0962 | 8 | 17 | 113 | 122 |
| php-src | 48 | 15 | 0.3125 | 7 | 8 | 15 | 18 |
| gpac | 66 | 14 | 0.2121 | 5 | 9 | 25 | 27 |
| vim | 82 | 12 | 0.1463 | 5 | 7 | 34 | 36 |
| mruby | 22 | 9 | 0.4091 | 4 | 5 | 6 | 7 |
| qemu | 22 | 8 | 0.3636 | 2 | 6 | 5 | 9 |
| linux-2.6 | 26 | 6 | 0.2308 | 3 | 3 | 10 | 10 |
| FreeRDP | 32 | 5 | 0.1562 | 4 | 1 | 15 | 12 |
| ImageMagick6 | 32 | 5 | 0.1562 | 2 | 3 | 13 | 14 |
| ghostpdl | 18 | 5 | 0.2778 | 1 | 4 | 5 | 8 |
| Pillow | 14 | 4 | 0.2857 | 2 | 2 | 5 | 5 |

## By Changed-Line Bucket

| changed_line_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 490 | 109 | 0.2224 | 49 | 60 | 186 | 195 |
| 03-05 | 482 | 71 | 0.1473 | 33 | 38 | 204 | 207 |
| 06-10 | 386 | 58 | 0.1503 | 28 | 30 | 160 | 168 |
| 11-25 | 275 | 47 | 0.1709 | 25 | 22 | 117 | 111 |
| 26+ | 159 | 45 | 0.2830 | 18 | 27 | 51 | 63 |

## By Confidence Bucket

| confidence_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.65-0.80 | 225 | 94 | 0.4178 | 56 | 38 | 64 | 67 |
| 0.95-1.00 | 1062 | 83 | 0.0782 | 43 | 40 | 493 | 486 |
| 0.80-0.95 | 315 | 80 | 0.2540 | 35 | 45 | 134 | 101 |
| 0.50-0.65 | 190 | 73 | 0.3842 | 19 | 54 | 27 | 90 |

## Highest-Confidence False Positives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 486837::pairctx | perl5 | cwe-120 | 0 | 1 | 1.0000 | 49 | CVE-2020-12723 |
| 269738::pairctx | electron | cwe-284 | 0 | 1 | 0.9946 | 6 | CVE-2020-15174 |
| 404192::pairctx | pcre2 | cwe-703 | 0 | 1 | 0.9945 | 97 | CVE-2022-1587 |
| 464942::pairctx | php-src | cwe-125 | 0 | 1 | 0.9941 | 6 | CVE-2020-7060 |
| 384543::pairctx | ceph | cwe-400 | 0 | 1 | 0.9938 | 3 | CVE-2020-1700 |
| 231012::pairctx | mruby | cwe-703 | 0 | 1 | 0.9922 | 5 | CVE-2022-1427 |
| 332375::pairctx | vim | cwe-787 | 0 | 1 | 0.9921 | 19 | CVE-2022-0318 |
| 242619::pairctx | tensorflow | cwe-703 | 0 | 1 | 0.9920 | 4 | CVE-2022-29195 |

## Lowest-Probability False Negatives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 202069::pairctx | linux | cwe-665 | 1 | 0 | 0.0008 | 85 | CVE-2021-46283 |
| 198476::pairctx | njs | cwe-416 | 1 | 0 | 0.0030 | 11 | CVE-2022-25139 |
| 195022::pairctx | glewlwyd | cwe-287 | 1 | 0 | 0.0036 | 4 | CVE-2021-45379 |
| 197848::pairctx | Pillow | cwe-125 | 1 | 0 | 0.0047 | 5 | CVE-2020-10378 |
| 206271::pairctx | bash | cwe-119 | 1 | 0 | 0.0047 | 5 | CVE-2012-6711 |
| 195023::pairctx | tensorflow | cwe-190 | 1 | 0 | 0.0052 | 18 | CVE-2022-23568 |
| 198143::pairctx | electron | cwe-284 | 1 | 0 | 0.0063 | 6 | CVE-2020-15174 |
| 213037::pairctx | php-src | cwe-125 | 1 | 0 | 0.0070 | 6 | CVE-2020-7060 |
