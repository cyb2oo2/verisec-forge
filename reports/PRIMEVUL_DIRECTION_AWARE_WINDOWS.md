# PrimeVul Direction-Aware Window Experiment

This experiment follows the `26+` large-diff error-window mining result. The goal is to test whether candidate-side operation direction can be made explicit in the input representation.

## Dataset

Input:

- `data/processed/primevul_diff_bucket_slices/eval_26plus.jsonl`

Generated direction-aware eval slice:

- `data/processed/primevul_diff_bucket_slices/eval_26plus_directional_h3_c2400.jsonl`
- summary: `reports/secure_code_primevul_pair_diff_bucket_26plus_directional_h3_c2400_summary.json`

Matched full train/eval slices for the next same-template experiment:

- train: `data/processed/secure_code_primevul_pair_diff_directional_train_balanced_3000_metadata.jsonl`
- eval: `data/processed/secure_code_primevul_pair_diff_directional_eval_balanced_1792_dedup_metadata.jsonl`
- train summary: `reports/secure_code_primevul_pair_diff_directional_train_balanced_3000_summary.json`
- eval summary: `reports/secure_code_primevul_pair_diff_directional_eval_balanced_1792_dedup_summary.json`
- training config: `configs/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_directional_3000_v1.json`
- `26+` bucket eval config: `configs/cls_eval_secure_code_primevul_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval_bucket_26plus_directional_h3_c2400.json`

Construction:

- keep up to `3` high-signal hunks
- apply a `2400` character diff-window budget before prompt wrapper text
- render counterpart-side and candidate-side changed lines separately
- add heuristic operation labels such as `candidate_adds_protection`, `candidate_removes_protection`, `candidate_introduces_risk`, and `candidate_removes_risk`

Length summary:

- rows: `159`
- original p50 chars: `2528`
- original p90 chars: `5404`
- original max chars: `10859`
- direction-aware p50 chars: `2488`
- direction-aware p90 chars: `2744`
- direction-aware max chars: `2755`

## Transfer Check

We evaluated the existing edge-focus checkpoint directly on the new direction-aware representation:

- checkpoint: `checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1`
- report: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval_bucket_26plus_directional_h3_c2400_report.json`
- threshold sweep: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`

Default threshold result:

| Accuracy | Recall | Specificity | Precision | F1 |
| ---: | ---: | ---: | ---: | ---: |
| `0.5094` | `0.0000` | `1.0000` | `0.0000` | `0.0000` |

Best balanced-accuracy threshold:

| Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.07` | `0.5377` | `0.3718` | `0.7037` | `0.5472` | `0.4427` |

## Same-Template Training

We then trained a matched LoRA sequence classifier on the direction-aware representation:

- checkpoint: `checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_directional_3000_v1`
- full eval report: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_report.json`
- full eval threshold sweep: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_threshold_sweep.json`
- `26+` bucket report: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval_bucket_26plus_directional_h3_c2400_report.json`
- `26+` bucket threshold sweep: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`

Full deduplicated eval:

| Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.5` | `0.8225` | `0.8268` | `0.8183` | `0.8195` | `0.8231` |

`26+` large-diff bucket:

| Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.4` | `0.7721` | `0.6923` | `0.8519` | `0.8182` | `0.7500` |

This is the first structural large-diff representation that improves the hard `26+` bucket over the previous edge-focus bucket result (`0.7438` balanced accuracy). The gain comes with a different operating profile: direction-aware windows favor specificity and precision more than raw edge-focus.

## Remaining Error Pattern

The follow-up error-window report uses the original raw `26+` diffs for interpretability while applying the direction-aware model predictions:

- report: `reports/PRIMEVUL_DIRECTION_AWARE_26PLUS_ERROR_WINDOWS.md`
- JSON: `reports/secure_code_primevul_pair_diff_directional_26plus_error_windows.json`

At the best balanced threshold (`0.4`), the `26+` bucket has:

- TP/TN/FP/FN: `54` / `69` / `12` / `24`
- old edge-focus at threshold `0.3`: `65` / `53` / `28` / `13`

So the new representation changes the failure mode. It sharply reduces false positives but increases false negatives. The aggregate direction labels show the remaining misses are not just empty/no-signal examples:

- FP top directions: `candidate_removes_protection` and `candidate_adds_protection` both appear `7` times
- FN top directions: `candidate_adds_protection` appears `18` times, `candidate_removes_protection` appears `12` times, and `candidate_introduces_risk` appears `9` times

The next training target is therefore not "add direction labels" in general. It is recall recovery for vulnerable rows where the top windows mix hardening-looking edits with risk-introducing edits.

## Recall-Recovery v1

The first recall-recovery dataset is built without using eval false negatives directly. It oversamples same-template train rows that match the hard training pattern:

- base train rows: `3000`
- output train rows: `3249`
- added rows: `249`
- all vulnerable `26+` rows repeated once: `143`
- mixed vulnerable `26+` rows repeated twice: `33` source rows
- safe `26+` anchors added: `40`
- label mix: `1709` vulnerable / `1540` safe
- summary: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_train_3249_summary.json`

Full deduplicated eval:

| Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| `0.5` | `0.8180` | `0.7732` | `0.8629` | `0.8491` | `0.8094` |

`26+` large-diff bucket:

| Selector | Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| best balanced | `0.8` | `0.7904` | `0.6795` | `0.9012` | `0.8689` | `0.7626` |
| best F1 | `0.7` | `0.7792` | `0.7436` | `0.8148` | `0.7945` | `0.7682` |
| default | `0.5` | `0.7502` | `0.8462` | `0.6543` | `0.7021` | `0.7674` |

This is a useful but nuanced result. The default threshold behaves like a recall-recovery mode and cuts `26+` false negatives from `24` to `12`, but false positives rise from `12` to `28`. After threshold calibration, the best balanced point reaches `0.7904`, the strongest `26+` result so far, with the same `8` false positives as the previous high-specificity point and `25` false negatives.

The lesson is that targeted oversampling changed the probability distribution more than it simply raised recall. Its value appears only when paired with threshold calibration.

## Recall-Recovery v2

The second ablation tested a more conservative recipe:

- base train rows: `3000`
- output train rows: `3113`
- added rows: `113`
- all vulnerable `26+` repeats: `0`
- mixed vulnerable `26+` rows repeated once: `33` source rows
- safe `26+` anchors added: `80`
- label mix: `1533` vulnerable / `1580` safe
- summary: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_train_3113_summary.json`

Results:

| Split | Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full dedup eval | `0.5` | `0.8074` | `0.7553` | `0.8595` | `0.8429` | `0.7967` |
| `26+` bucket | `0.4` | `0.7077` | `0.5513` | `0.8642` | `0.7963` | `0.6515` |

This is a negative ablation. Adding more safe anchors while reducing vulnerable duplication makes the model too conservative and damages both the full eval score and the hard `26+` bucket. The v1 recipe remains the better recall-recovery branch.

## Bucket Router v1

The calibration follow-up keeps the baseline direction-aware detector for all non-`26+` rows and routes only `26+` large-diff rows through the recall-recovery v1 checkpoint.

Artifacts:

- report: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER.md`
- JSON: `reports/secure_code_primevul_directional_bucket_router_v1_report.json`
- recall-friendly report: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_RECALL.md`
- recall-friendly JSON: `reports/secure_code_primevul_directional_bucket_router_v1_recall_report.json`

Results on the full deduplicated eval set:

| Bucket Threshold | Balanced Accuracy | Recall | Specificity | Precision | F1 | Interpretation |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `0.8` | `0.8231` | `0.8291` | `0.8172` | `0.8190` | `0.8240` | specificity-preserving route |
| `0.7` | `0.8231` | `0.8346` | `0.8116` | `0.8155` | `0.8250` | recall-friendlier route |

Pair/group metrics:

| Bucket Threshold | Group All-Correct Rate | Orientation Accuracy | Unique Pair Groups | Eligible Mixed-Label Pairs |
| ---: | ---: | ---: | ---: | ---: |
| `0.8` | `0.7241` | `0.8624` | `877` | `850` |
| `0.7` | `0.7229` | `0.8624` | `877` | `850` |

This is a small but useful systems result. The router does not create a dramatic new headline score, but it preserves the full paired-diff operating band while making the large-diff recall/specificity tradeoff explicit and configurable. That is cleaner than forcing one global checkpoint and one global threshold across very different changed-line buckets.

## Validation-Selected Bucket Router

The next check avoids selecting the bucket threshold directly on the full eval set. It splits the paired eval rows by `pair_key`, uses `30%` of pair groups for calibration, and reports the selected router on the remaining held-out pair groups.

Artifacts:

- report: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_CALIBRATED.md`
- JSON: `reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json`

Protocol:

- split seed: `42`
- calibration pair groups: `263`
- held-out eval pair groups: `614`
- selector: `balanced_accuracy`
- selected bucket threshold: `0.8`

Held-out eval comparison:

| System | Balanced Accuracy | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline direction-aware | `0.8136` | `0.8143` | `0.8130` | `0.8136` | `0.7101` | `0.8514` |
| calibrated bucket router | `0.8136` | `0.8159` | `0.8114` | `0.8139` | `0.7134` | `0.8581` |

This makes the router claim more conservative. The row-level score is essentially flat on the held-out split, but pair/group metrics improve slightly. The best interpretation is that bucket routing improves comparative consistency on paired samples, not that it creates a new raw-accuracy breakthrough.

## Router Statistical Check

The held-out router result now has a bootstrap uncertainty check and paired sign tests at the pair-group level.

Artifacts:

- report: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_STATISTICS.md`
- JSON: `reports/secure_code_primevul_directional_bucket_router_statistics_v1.json`

Bootstrap 95% confidence intervals:

| System | Metric | Observed | 95% CI |
| --- | --- | ---: | --- |
| baseline | group all-correct | `0.7101` | `0.6743-0.7443` |
| router | group all-correct | `0.7134` | `0.6792-0.7476` |
| baseline | orientation | `0.8514` | `0.8217-0.8790` |
| router | orientation | `0.8581` | `0.8289-0.8844` |

Router minus baseline:

| Metric | Delta | Bootstrap 95% CI | Sign Test |
| --- | ---: | --- | --- |
| group all-correct | `+0.0033` | `-0.0065-0.0147` | wins `6`, losses `4`, p=`0.753906` |
| orientation | `+0.0068` | `0.0017-0.0151` | wins `4`, losses `0`, p=`0.125` |

This sharpens the claim again. The group all-correct gain is not statistically convincing. The orientation gain has a positive bootstrap interval, but the exact sign test is underpowered because almost all pair groups are ties. The safe conclusion is: bucket routing shows a small, directionally positive consistency signal, but it needs larger or external splits before being treated as a decisive improvement.

## Pair-Coupled Router

The next system layer uses the paired benchmark structure directly. It does not use gold labels. For pair groups with at least two rows, it assigns the highest-probability side as vulnerable and the remaining side as safe when the calibrated probability gap is large enough.

Artifacts:

- report: `reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md`
- JSON: `reports/secure_code_primevul_pair_coupled_router_v1_report.json`
- statistics: `reports/PRIMEVUL_PAIR_COUPLED_ROUTER_STATISTICS.md`
- statistics JSON: `reports/secure_code_primevul_pair_coupled_router_statistics_v1.json`

Protocol:

- selector: `orientation_accuracy`
- selected margin: `0.02`
- held-out eval pair groups: `614`

Held-out comparison:

| System | Balanced Accuracy | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline direction-aware | `0.8136` | `0.8143` | `0.8130` | `0.8136` | `0.7101` | `0.8514` |
| bucket router | `0.8136` | `0.8159` | `0.8114` | `0.8139` | `0.7134` | `0.8581` |
| pair-coupled router | `0.8493` | `0.8492` | `0.8494` | `0.8492` | `0.8208` | `0.8581` |

Pair-coupled minus bucket router:

| Metric | Delta | Bootstrap 95% CI | Sign Test |
| --- | ---: | --- | --- |
| group all-correct | `+0.1075` | `0.0814-0.1336` | wins `72`, losses `6`, p<`0.000001` |
| orientation | `0.0000` | `0.0000-0.0000` | unchanged |

This is a stronger system result than row-level bucket routing. It improves discrete pair consistency because it changes labels, not probability ordering. Therefore orientation remains unchanged by design, while group all-correct and row-level balanced accuracy improve substantially.

## Pair-Coupled Multi-Split Stability

The pair-coupled result is now checked across five independent pair-key calibration/eval split seeds.

Artifacts:

- balanced-selector report: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`
- balanced-selector JSON: `reports/secure_code_primevul_pair_coupled_multisplit_balanced_v1.json`
- group-selector report: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT.md`
- group-selector JSON: `reports/secure_code_primevul_pair_coupled_multisplit_v1.json`

Balanced-selector summary across seeds `7,13,42,99,123`:

| Metric | Mean | Stdev | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| baseline balanced accuracy | `0.8220` | `0.0082` | `0.8136` | `0.8311` |
| bucket-router balanced accuracy | `0.8224` | `0.0072` | `0.8136` | `0.8312` |
| pair-coupled balanced accuracy | `0.8572` | `0.0061` | `0.8493` | `0.8644` |
| bucket-router group all-correct | `0.7228` | `0.0101` | `0.7134` | `0.7394` |
| pair-coupled group all-correct | `0.8339` | `0.0124` | `0.8208` | `0.8502` |
| pair minus bucket balanced accuracy | `+0.0348` | `0.0025` | `+0.0317` | `+0.0384` |
| pair minus bucket group all-correct | `+0.1111` | `0.0101` | `+0.1010` | `+0.1271` |

Every split seed shows a positive pair-coupled delta. Row-level McNemar p-values are favorable on all five splits, and group all-correct sign tests report wins over losses on all five splits. This addresses the main statistical hygiene concern for the pair-coupled layer much more directly than the earlier single-split report.

## Interpretation

This is a negative transfer result. The direction-aware prompt is not a free inference-time improvement for a checkpoint trained on raw diff-only inputs. The model treats the new template as a distribution shift and collapses toward safe predictions at the default threshold.

The transfer result did not disprove the direction-aware hypothesis. It narrowed the experiment, and same-template training confirmed that the representation is viable. The full-eval score remains inside the established paired-diff operating band, while the `26+` bucket improves beyond the previous best bucket result.

## Next Step

The next promising ablation is evidence localization inside the pair-coupled system. The decision layer now uses pair structure well; the next missing piece is explaining which changed hunk caused the vulnerable side to outrank the fixed/safe side.
