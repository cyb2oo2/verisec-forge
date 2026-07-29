# PrimeVul Predicted-Side Failure Taxonomy

> **HISTORICAL DOCUMENT — CONTAINS WITHDRAWN RESULTS.**
> Contains results or interpretations withdrawn after adversarial structural-control
> analysis. Under the closed-world pair constraint the detector reaches `0.8596` balanced
> accuracy and a semantics-free character-level diff control reaches `0.8588` on the same
> population; the difference (`+0.0008`, clustered 95% CI `[-0.0202, +0.0222]`, sign test
> 19 vs 18, `p=1.0`) is not distinguishable from zero.
> **Do not cite as the repository's current scientific conclusion.**
> Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).


This report analyzes rows where pair-coupled predicted side disagrees with the gold side, then inspects the top hunk selected by the predicted-side localizer.

## Summary

- Matched sources: `1257`
- Side accuracy: `0.8488`
- Wrong sources: `190`
- False positives / false negatives: `95` / `95`
- Wrong top-hunk positive rate: `0.0632`
- Correct top-hunk positive rate: `0.761`

## by_mistake_type

| value | count |
| --- | ---: |
| false_positive | 95 |
| false_negative | 95 |

## by_changed_line_bucket

| value | count |
| --- | ---: |
| 00-02 | 59 |
| 03-05 | 45 |
| 11-25 | 38 |
| 06-10 | 27 |
| 26+ | 21 |

## by_gap_bucket

| value | count |
| --- | ---: |
| 50+ | 86 |
| 20-50 | 36 |
| 00-02 | 25 |
| 05-10 | 21 |
| 10-20 | 14 |
| 02-05 | 8 |

## by_project

| value | count |
| --- | ---: |
| linux | 35 |
| tensorflow | 17 |
| php-src | 8 |
| vim | 6 |
| gpac | 6 |
| gst-plugins-good | 4 |
| ImageMagick6 | 4 |
| rizin | 4 |
| mruby | 3 |
| qpdf | 3 |
| FreeRDP | 3 |
| libjpeg | 3 |
| qemu | 3 |
| server | 3 |
| libyang | 3 |
| wireless-drivers | 2 |
| squid | 2 |
| ImageMagick | 2 |
| gnutls | 2 |
| FFmpeg | 2 |

## by_vulnerability_type

| value | count |
| --- | ---: |
| cwe-787 | 29 |
| cwe-416 | 20 |
| cwe-125 | 16 |
| cwe-703 | 12 |
| cwe-415 | 10 |
| cwe-190 | 9 |
| cwe-362 | 7 |
| cwe-189 | 6 |
| cwe-665 | 6 |
| cwe-476 | 6 |
| cwe-401 | 6 |
| cwe-119 | 5 |
| cwe-835 | 5 |
| cwe-400 | 4 |
| cwe-78 | 4 |
| cwe-399 | 3 |
| cwe-200 | 3 |
| cwe-284 | 3 |
| cwe-909 | 2 |
| cwe-20 | 2 |

## by_top_direction_label

| value | count |
| --- | ---: |
| direction_unclear | 65 |
| candidate_adds_protection | 58 |
| candidate_removes_protection | 54 |
| candidate_removes_risk | 21 |
| candidate_introduces_risk | 16 |

## by_route

| value | count |
| --- | ---: |
| default | 169 |
| bucket | 21 |

## High-Score Wrong Examples

| source_id | type | bucket | gap | project | cwe | top_labels | top_score |
| --- | --- | --- | ---: | --- | --- | --- | ---: |
| 245427::pairctx | false_positive | 26+ | 0.651 | tensorflow | cwe-787 | candidate_removes_protection,candidate_removes_risk | 273.5867 |
| 196800::pairctx | false_negative | 26+ | 0.651 | tensorflow | cwe-787 | candidate_adds_protection,candidate_introduces_risk | 264.9116 |
| 328360::pairctx | false_positive | 26+ | 0.1369 | linux | cwe-665 | candidate_removes_protection,candidate_introduces_risk | 225.4154 |
| 202069::pairctx | false_negative | 26+ | 0.1369 | linux | cwe-665 | candidate_adds_protection,candidate_removes_risk | 218.2782 |
| 220804::pairctx | false_positive | 26+ | 0.2922 | tensorflow | cwe-787 | candidate_removes_protection | 178.1 |
| 400219::pairctx | false_positive | 26+ | 0.7687 | openssh-portable | cwe-399 | candidate_removes_protection,candidate_removes_risk | 176.8866 |
| 195055::pairctx | false_negative | 26+ | 0.2922 | tensorflow | cwe-787 | candidate_adds_protection | 172.5247 |
| 207709::pairctx | false_negative | 26+ | 0.7687 | openssh-portable | cwe-399 | candidate_adds_protection,candidate_introduces_risk | 171.3361 |
| 499640::pairctx | false_positive | 11-25 | 0.8649 | cpio | cwe-190 | candidate_removes_protection,candidate_removes_risk | 128.95 |
| 216101::pairctx | false_negative | 11-25 | 0.8649 | cpio | cwe-190 | candidate_adds_protection,candidate_introduces_risk | 124.895 |
| 268829::pairctx | false_positive | 26+ | 0.2429 | radare2 | cwe-78 | candidate_removes_protection,candidate_removes_risk | 114.1145 |
| 198095::pairctx | false_negative | 26+ | 0.2429 | radare2 | cwe-78 | candidate_adds_protection,candidate_introduces_risk | 110.6898 |
| 417234::pairctx | false_positive | 11-25 | 0.7986 | gnutls | cwe-189 | candidate_removes_protection | 101.648 |
| 224281::pairctx | false_positive | 26+ | 0.1915 | squid | cwe-400 | candidate_removes_protection,candidate_removes_risk | 101.5801 |
| 195309::pairctx | false_negative | 26+ | 0.1915 | squid | cwe-400 | candidate_adds_protection,candidate_introduces_risk | 98.6171 |
| 209003::pairctx | false_negative | 11-25 | 0.7986 | gnutls | cwe-189 | candidate_adds_protection | 98.4513 |
| 381036::pairctx | false_positive | 26+ | 0.738 | ImageMagick6 | cwe-125 | candidate_removes_protection | 74.0794 |
| 206422::pairctx | false_negative | 26+ | 0.738 | ImageMagick6 | cwe-125 | candidate_adds_protection | 71.8864 |
| 432423::pairctx | false_positive | 11-25 | 0.7286 | linux | cwe-401 | candidate_removes_protection,candidate_introduces_risk | 71.8257 |
| 210296::pairctx | false_negative | 11-25 | 0.7286 | linux | cwe-401 | candidate_adds_protection,candidate_removes_risk | 69.637 |

## Interpretation

A low wrong top-hunk positive rate means the localizer is ranking evidence that aligns with the predicted side but disagrees with the gold side. In this run, wrong-side rows are therefore not mainly a hunk-ranking failure; they are upstream side-decision failures that propagate into evidence selection. The next lever is pair-side decision calibration and hard negative handling.
