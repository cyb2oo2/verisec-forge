# PrimeVul Paired Diff Failure Analysis

This report is generated from the diff-only paired eval predictions by `scripts/analyze_primevul_diff_failures.py`.

## Summary

- Threshold: `0.5000`
- Accuracy: `0.8348`
- Recall: `0.7966`
- Specificity: `0.8729`
- Precision: `0.8622`
- Errors: `114` false positives and `182` false negatives out of `1792` examples
- Pair groups: `877` unique groups
- Group all-correct rate: `0.7366`
- Orientation accuracy: `0.8447`

## By CWE

| vulnerability_type | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cwe-787 | 296 | 43 | 0.1453 | 14 | 29 | 120 | 133 |
| cwe-125 | 214 | 33 | 0.1542 | 11 | 22 | 84 | 97 |
| cwe-703 | 158 | 23 | 0.1456 | 12 | 11 | 68 | 67 |
| cwe-416 | 105 | 23 | 0.2190 | 8 | 15 | 39 | 43 |
| cwe-476 | 164 | 18 | 0.1098 | 6 | 12 | 70 | 76 |
| cwe-190 | 61 | 12 | 0.1967 | 3 | 9 | 22 | 27 |
| cwe-415 | 32 | 11 | 0.3438 | 5 | 6 | 10 | 11 |
| cwe-119 | 52 | 9 | 0.1731 | 5 | 4 | 20 | 23 |
| cwe-835 | 24 | 8 | 0.3333 | 2 | 6 | 6 | 10 |
| cwe-200 | 59 | 7 | 0.1186 | 2 | 5 | 24 | 28 |
| cwe-120 | 38 | 7 | 0.1842 | 4 | 3 | 16 | 15 |
| cwe-20 | 48 | 6 | 0.1250 | 3 | 3 | 21 | 21 |

## By Project

| project | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| linux | 256 | 45 | 0.1758 | 20 | 25 | 103 | 108 |
| tensorflow | 260 | 20 | 0.0769 | 7 | 13 | 117 | 123 |
| php-src | 48 | 13 | 0.2708 | 3 | 10 | 13 | 22 |
| gpac | 66 | 10 | 0.1515 | 4 | 6 | 28 | 28 |
| vim | 82 | 9 | 0.1098 | 3 | 6 | 35 | 38 |
| mruby | 22 | 9 | 0.4091 | 4 | 5 | 6 | 7 |
| qemu | 22 | 7 | 0.3182 | 2 | 5 | 6 | 9 |
| ghostpdl | 18 | 6 | 0.3333 | 4 | 2 | 7 | 5 |
| FreeRDP | 32 | 5 | 0.1562 | 0 | 5 | 11 | 16 |
| linux-2.6 | 26 | 5 | 0.1923 | 4 | 1 | 12 | 9 |
| openssl | 18 | 5 | 0.2778 | 2 | 3 | 6 | 7 |
| ImageMagick6 | 32 | 4 | 0.1250 | 2 | 2 | 14 | 14 |

## By Changed-Line Bucket

| changed_line_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 490 | 90 | 0.1837 | 24 | 66 | 180 | 220 |
| 03-05 | 482 | 63 | 0.1307 | 25 | 38 | 204 | 215 |
| 06-10 | 386 | 55 | 0.1425 | 21 | 34 | 156 | 175 |
| 11-25 | 275 | 44 | 0.1600 | 25 | 19 | 120 | 111 |
| 26+ | 159 | 44 | 0.2767 | 19 | 25 | 53 | 62 |

## By Confidence Bucket

| confidence_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.80-0.95 | 445 | 85 | 0.1910 | 30 | 55 | 163 | 197 |
| 0.50-0.65 | 216 | 85 | 0.3935 | 36 | 49 | 70 | 61 |
| 0.65-0.80 | 248 | 67 | 0.2702 | 20 | 47 | 80 | 101 |
| 0.95-1.00 | 883 | 59 | 0.0668 | 28 | 31 | 400 | 424 |

## Highest-Confidence False Positives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 441966::pairctx | linux | cwe-787 | 0 | 1 | 0.9976 | 10 | CVE-2020-10942 |
| 241321::pairctx | nDPI | cwe-125 | 0 | 1 | 0.9967 | 49 | CVE-2020-15473 |
| 404192::pairctx | pcre2 | cwe-703 | 0 | 1 | 0.9965 | 97 | CVE-2022-1587 |
| 219947::pairctx | glewlwyd | cwe-287 | 0 | 1 | 0.9947 | 4 | CVE-2021-45379 |
| 269738::pairctx | electron | cwe-284 | 0 | 1 | 0.9945 | 6 | CVE-2020-15174 |
| 379446::pairctx | bash | cwe-119 | 0 | 1 | 0.9939 | 5 | CVE-2012-6711 |
| 242619::pairctx | tensorflow | cwe-703 | 0 | 1 | 0.9928 | 4 | CVE-2022-29195 |
| 464942::pairctx | php-src | cwe-125 | 0 | 1 | 0.9903 | 6 | CVE-2020-7060 |

## Lowest-Probability False Negatives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 207755::pairctx | php-src | cwe-200 | 1 | 0 | 0.0017 | 53 | CVE-2012-6113 |
| 198095::pairctx | radare2 | cwe-78 | 1 | 0 | 0.0020 | 137 | CVE-2020-15121 |
| 202069::pairctx | linux | cwe-665 | 1 | 0 | 0.0039 | 85 | CVE-2021-46283 |
| 197848::pairctx | Pillow | cwe-125 | 1 | 0 | 0.0057 | 5 | CVE-2020-10378 |
| 195691::pairctx | mruby | cwe-703 | 1 | 0 | 0.0070 | 5 | CVE-2022-1427 |
| 198143::pairctx | electron | cwe-284 | 1 | 0 | 0.0089 | 6 | CVE-2020-15174 |
| 210527::pairctx | linux | cwe-415 | 1 | 0 | 0.0090 | 1 | CVE-2022-28389 |
| 206271::pairctx | bash | cwe-119 | 1 | 0 | 0.0093 | 5 | CVE-2012-6711 |
