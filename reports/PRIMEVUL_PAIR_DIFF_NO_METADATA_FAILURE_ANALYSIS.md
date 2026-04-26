# PrimeVul Paired Diff Failure Analysis

This report is generated from the diff-only paired eval predictions by `scripts/analyze_primevul_diff_failures.py`.

## Summary

- Threshold: `0.8000`
- Accuracy: `0.8244`
- Recall: `0.7533`
- Specificity: `0.8956`
- Precision: `0.8782`
- Errors: `94` false positives and `222` false negatives out of `1800` examples
- Pair groups: `878` unique groups
- Group all-correct rate: `0.7107`
- Orientation accuracy: `0.8435`

## By CWE

| vulnerability_type | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cwe-787 | 294 | 51 | 0.1735 | 13 | 38 | 109 | 134 |
| cwe-125 | 215 | 38 | 0.1767 | 12 | 26 | 82 | 95 |
| cwe-416 | 107 | 25 | 0.2336 | 6 | 19 | 34 | 48 |
| cwe-703 | 160 | 24 | 0.1500 | 11 | 13 | 66 | 70 |
| cwe-476 | 162 | 20 | 0.1235 | 5 | 15 | 68 | 74 |
| cwe-190 | 61 | 14 | 0.2295 | 3 | 11 | 19 | 28 |
| cwe-415 | 31 | 12 | 0.3871 | 4 | 8 | 8 | 11 |
| cwe-200 | 61 | 9 | 0.1475 | 4 | 5 | 25 | 27 |
| cwe-119 | 56 | 9 | 0.1607 | 3 | 6 | 22 | 25 |
| cwe-120 | 37 | 8 | 0.2162 | 2 | 6 | 13 | 16 |
| cwe-665 | 12 | 7 | 0.5833 | 4 | 3 | 3 | 2 |
| cwe-835 | 24 | 6 | 0.2500 | 1 | 5 | 7 | 11 |

## By Project

| project | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| linux | 257 | 49 | 0.1907 | 17 | 32 | 95 | 113 |
| tensorflow | 258 | 25 | 0.0969 | 7 | 18 | 111 | 122 |
| php-src | 51 | 17 | 0.3333 | 6 | 11 | 15 | 19 |
| gpac | 68 | 12 | 0.1765 | 6 | 6 | 28 | 28 |
| vim | 84 | 10 | 0.1190 | 2 | 8 | 34 | 40 |
| mruby | 22 | 8 | 0.3636 | 2 | 6 | 5 | 9 |
| FreeRDP | 32 | 7 | 0.2188 | 1 | 6 | 10 | 15 |
| qemu | 22 | 7 | 0.3182 | 1 | 6 | 5 | 10 |
| linux-2.6 | 25 | 5 | 0.2000 | 1 | 4 | 9 | 11 |
| ImageMagick6 | 32 | 4 | 0.1250 | 1 | 3 | 13 | 15 |
| ghostpdl | 18 | 4 | 0.2222 | 1 | 3 | 6 | 8 |
| Pillow | 13 | 4 | 0.3077 | 2 | 2 | 4 | 5 |

## By Changed-Line Bucket

| changed_line_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00-02 | 484 | 98 | 0.2025 | 22 | 76 | 168 | 218 |
| 03-05 | 488 | 73 | 0.1496 | 21 | 52 | 191 | 224 |
| 06-10 | 396 | 53 | 0.1338 | 17 | 36 | 161 | 182 |
| 11-25 | 275 | 46 | 0.1673 | 19 | 27 | 111 | 118 |
| 26+ | 157 | 46 | 0.2930 | 15 | 31 | 47 | 64 |

## By Confidence Bucket

| confidence_bucket | Total | Errors | Error Rate | FP | FN | TP | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.95-1.00 | 1159 | 101 | 0.0871 | 53 | 48 | 550 | 508 |
| 0.80-0.95 | 306 | 82 | 0.2680 | 41 | 41 | 128 | 96 |
| 0.65-0.80 | 175 | 67 | 0.3829 | 0 | 67 | 0 | 108 |
| 0.50-0.65 | 160 | 66 | 0.4125 | 0 | 66 | 0 | 94 |

## Highest-Confidence False Positives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 263524::pairctx | tensorflow | cwe-369 | 0 | 1 | 1.0000 | 77 | CVE-2021-29547 |
| 243213::pairctx | gpac | cwe-401 | 0 | 1 | 0.9998 | 38 | CVE-2021-32138 |
| 503867::pairctx | guile | cwe-275 | 0 | 1 | 0.9991 | 23 | CVE-2016-8605 |
| 269738::pairctx | electron | cwe-284 | 0 | 1 | 0.9983 | 6 | CVE-2020-15174 |
| 242619::pairctx | tensorflow | cwe-703 | 0 | 1 | 0.9970 | 4 | CVE-2022-29195 |
| 441966::pairctx | linux | cwe-787 | 0 | 1 | 0.9968 | 10 | CVE-2020-10942 |
| 323088::pairctx | slurm | cwe-362 | 0 | 1 | 0.9962 | 6 | CVE-2020-27746 |
| 274032::pairctx | mruby | cwe-415 | 0 | 1 | 0.9962 | 1 | CVE-2020-36401 |

## Lowest-Probability False Negatives

| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 206874::pairctx | FreeRDP | cwe-125 | 1 | 0 | 0.0002 | 83 | CVE-2020-11085 |
| 197499::pairctx | gpac | cwe-416 | 1 | 0 | 0.0011 | 101 | CVE-2022-2453 |
| 197178::pairctx | nDPI | cwe-125 | 1 | 0 | 0.0012 | 89 | CVE-2020-15472 |
| 198143::pairctx | electron | cwe-284 | 1 | 0 | 0.0013 | 6 | CVE-2020-15174 |
| 209102::pairctx | vim | cwe-703 | 1 | 0 | 0.0016 | 131 | CVE-2022-2980 |
| 197848::pairctx | Pillow | cwe-125 | 1 | 0 | 0.0024 | 5 | CVE-2020-10378 |
| 198402::pairctx | mruby | cwe-415 | 1 | 0 | 0.0026 | 1 | CVE-2020-36401 |
| 210873::pairctx | linux | cwe-787 | 1 | 0 | 0.0028 | 10 | CVE-2020-10942 |
