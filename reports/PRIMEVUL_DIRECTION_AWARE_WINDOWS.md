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

## Interpretation

This is a negative transfer result. The direction-aware prompt is not a free inference-time improvement for a checkpoint trained on raw diff-only inputs. The model treats the new template as a distribution shift and collapses toward safe predictions at the default threshold.

The transfer result did not disprove the direction-aware hypothesis. It narrowed the experiment, and same-template training confirmed that the representation is viable. The full-eval score remains inside the established paired-diff operating band, while the `26+` bucket improves beyond the previous best bucket result.

## Next Step

Run a second recall-recovery ablation with less vulnerable duplication or more safe anchors. The goal is to keep the `0.7904` bucket gain while improving full-eval balanced accuracy back toward the `0.8225` direction-aware baseline.
