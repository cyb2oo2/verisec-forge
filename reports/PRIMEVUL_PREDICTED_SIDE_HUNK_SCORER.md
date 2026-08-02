# PrimeVul Predicted-Side Hunk Scorer

> **STATUS: WITHDRAWN AS LOCALIZATION ACCURACY.**
> The `pseudo_label` target is produced by `support_label_for_decision`, which is antisymmetric in the decision argument: whenever risk_support != safety_support, flipping the predicted side flips the target deterministically. The side-correct (`0.7610`) versus side-wrong (`0.0632`) contrast is therefore an identity of the labelling function, not a measurement of evidence quality, and no model evidence output enters the target. Superseded by `reports/PRIMEVUL_EVIDENCE_HEURISTIC_CONSISTENCY.md`, which reports the same computation under an accurate name.
> See [Research Integrity Verification](../docs/RESEARCH_INTEGRITY_VERIFICATION.md) and [Remediation Notice](../docs/RESEARCH_INTEGRITY_REMEDIATION.md).


This report turns the side-aware hunk+window scorer from an oracle diagnostic into an end-to-end propagation check. The scorer is still trained on pseudo labels, but eval-time feature alignment uses the pair-coupled predicted side instead of the gold side.

## Side Source

| side source | matched sources | matched rows | side accuracy | missing sources |
| --- | ---: | ---: | ---: | ---: |
| oracle | 1787 | 9160 | n/a | n/a |
| pair_coupled_pred | 1257 | 6498 | 0.8488 | 530 |
| pre_coupled_pred | 1257 | 6498 | 0.813 | 530 |

## Top-K Coverage

| scorer | k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| oracle_side_aware_all | 1 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| oracle_side_aware_all | 2 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| oracle_side_aware_all | 3 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| oracle_side_aware_all | 5 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| oracle_side_aware_all | 8 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| oracle_side_aware_matched | 1 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| oracle_side_aware_matched | 2 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| oracle_side_aware_matched | 3 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| oracle_side_aware_matched | 5 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| oracle_side_aware_matched | 8 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| pair_coupled_predicted_side | 1 | 0.6555 | 0.6444 | 0.6667 | 824 | 1257 |
| pair_coupled_predicted_side | 2 | 0.6611 | 0.654 | 0.6683 | 831 | 1257 |
| pair_coupled_predicted_side | 3 | 0.6706 | 0.6635 | 0.6778 | 843 | 1257 |
| pair_coupled_predicted_side | 5 | 0.6858 | 0.6762 | 0.6954 | 862 | 1257 |
| pair_coupled_predicted_side | 8 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| pre_coupled_predicted_side | 1 | 0.65 | 0.6365 | 0.6635 | 817 | 1257 |
| pre_coupled_predicted_side | 2 | 0.6531 | 0.6397 | 0.6667 | 821 | 1257 |
| pre_coupled_predicted_side | 3 | 0.6643 | 0.6524 | 0.6762 | 835 | 1257 |
| pre_coupled_predicted_side | 5 | 0.6818 | 0.6667 | 0.697 | 857 | 1257 |
| pre_coupled_predicted_side | 8 | 0.7184 | 0.7127 | 0.7241 | 903 | 1257 |
| pair_coupled_predicted_side_correct_only | 1 | 0.761 | 0.7458 | 0.7763 | 812 | 1067 |
| pair_coupled_predicted_side_correct_only | 2 | 0.761 | 0.7458 | 0.7763 | 812 | 1067 |
| pair_coupled_predicted_side_correct_only | 3 | 0.761 | 0.7458 | 0.7763 | 812 | 1067 |
| pair_coupled_predicted_side_correct_only | 5 | 0.761 | 0.7458 | 0.7763 | 812 | 1067 |
| pair_coupled_predicted_side_correct_only | 8 | 0.761 | 0.7458 | 0.7763 | 812 | 1067 |
| pair_coupled_predicted_side_wrong_only | 1 | 0.0632 | 0.0737 | 0.0526 | 12 | 190 |
| pair_coupled_predicted_side_wrong_only | 2 | 0.1 | 0.1368 | 0.0632 | 19 | 190 |
| pair_coupled_predicted_side_wrong_only | 3 | 0.1632 | 0.2 | 0.1263 | 31 | 190 |
| pair_coupled_predicted_side_wrong_only | 5 | 0.2632 | 0.2842 | 0.2421 | 50 | 190 |
| pair_coupled_predicted_side_wrong_only | 8 | 0.4789 | 0.5263 | 0.4316 | 91 | 190 |

## Interpretation

The oracle side-aware score is an upper bound because it aligns evidence to the known target side. The pair-coupled predicted-side score is the deployment-facing diagnostic: any gap between these rows measures error propagation from the detector/pair-coupling layer into evidence localization.
