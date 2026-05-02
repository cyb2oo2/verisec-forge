# PrimeVul Confident Side-Inversion Set

This report builds a hard-negative calibration set from pair-coupled predictions that are wrong with a large probability gap. It targets confident side inversions rather than ambiguous near-ties.

## Summary

- Minimum gap: `0.5`
- Rows: `86`
- Pair groups: `43`
- False positives / false negatives: `43` / `43`
- Avg gap: `0.8225`
- Gap range: `0.5423` - `0.9836`

## by_mistake_type

| value | count |
| --- | ---: |
| false_negative | 43 |
| false_positive | 43 |

## by_changed_line_bucket

| value | count |
| --- | ---: |
| 03-05 | 24 |
| 11-25 | 22 |
| 06-10 | 18 |
| 00-02 | 16 |
| 26+ | 6 |

## by_project

| value | count |
| --- | ---: |
| linux | 16 |
| tensorflow | 10 |
| php-src | 6 |
| vim | 4 |
| gpac | 4 |
| ImageMagick6 | 4 |
| electron | 2 |
| src | 2 |
| mruby | 2 |
| wireless-drivers | 2 |
| shapelib | 2 |
| gst-plugins-good | 2 |
| bash | 2 |
| ceph | 2 |
| njs | 2 |
| neomutt | 2 |
| cpio | 2 |
| util-linux | 2 |
| rizin | 2 |
| gnutls | 2 |

## by_vulnerability_type

| value | count |
| --- | ---: |
| cwe-787 | 12 |
| cwe-703 | 10 |
| cwe-415 | 8 |
| cwe-416 | 8 |
| cwe-125 | 8 |
| cwe-476 | 4 |
| cwe-119 | 4 |
| cwe-401 | 4 |
| cwe-190 | 4 |
| cwe-189 | 4 |
| cwe-284 | 2 |
| cwe-122 | 2 |
| cwe-835 | 2 |
| cwe-400 | 2 |
| cwe-399 | 2 |
| cwe-824 | 2 |
| cwe-362 | 2 |
| cwe-252 | 2 |
| cwe-78 | 2 |
| cwe-200 | 2 |

## by_route

| value | count |
| --- | ---: |
| default | 80 |
| bucket | 6 |

## Highest-Gap Examples

| id | type | gap | bucket | project | cwe | cve |
| --- | --- | ---: | --- | --- | --- | --- |
| 198143::pairctx | false_negative | 0.9836 | 06-10 | electron | cwe-284 | CVE-2020-15174 |
| 269738::pairctx | false_positive | 0.9836 | 06-10 | electron | cwe-284 | CVE-2020-15174 |
| 206676::pairctx | false_negative | 0.9816 | 00-02 | vim | cwe-122 | CVE-2021-3903 |
| 384767::pairctx | false_positive | 0.9816 | 00-02 | vim | cwe-122 | CVE-2021-3903 |
| 421514::pairctx | false_positive | 0.9751 | 03-05 | src | cwe-476 | CVE-2020-35680 |
| 209807::pairctx | false_negative | 0.9751 | 03-05 | src | cwe-476 | CVE-2020-35680 |
| 274032::pairctx | false_positive | 0.9652 | 00-02 | mruby | cwe-415 | CVE-2020-36401 |
| 198402::pairctx | false_negative | 0.9652 | 00-02 | mruby | cwe-415 | CVE-2020-36401 |
| 195073::pairctx | false_negative | 0.9642 | 00-02 | tensorflow | cwe-416 | CVE-2022-23584 |
| 221123::pairctx | false_positive | 0.9642 | 00-02 | tensorflow | cwe-416 | CVE-2022-23584 |
| 242619::pairctx | false_positive | 0.9621 | 03-05 | tensorflow | cwe-703 | CVE-2022-29195 |
| 196689::pairctx | false_negative | 0.9621 | 03-05 | tensorflow | cwe-703 | CVE-2022-29195 |
| 318099::pairctx | false_positive | 0.959 | 00-02 | wireless-drivers | cwe-415 | CVE-2019-15504 |
| 201353::pairctx | false_negative | 0.959 | 00-02 | wireless-drivers | cwe-415 | CVE-2019-15504 |
| 437003::pairctx | false_positive | 0.9541 | 00-02 | linux | cwe-415 | CVE-2022-28389 |
| 210527::pairctx | false_negative | 0.9541 | 00-02 | linux | cwe-415 | CVE-2022-28389 |
| 204073::pairctx | false_negative | 0.9509 | 00-02 | shapelib | cwe-415 | CVE-2022-0699 |
| 351182::pairctx | false_positive | 0.9509 | 00-02 | shapelib | cwe-415 | CVE-2022-0699 |
| 215038::pairctx | false_negative | 0.9439 | 00-02 | gst-plugins-good | cwe-125 | CVE-2016-9810 |
| 482692::pairctx | false_positive | 0.9439 | 00-02 | gst-plugins-good | cwe-125 | CVE-2016-9810 |

## Intended Use

Use this as a targeted calibration or hard-negative mining artifact for pair-side decision models. It should not be treated as an independent benchmark split because it is selected from current model failures.
