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

## Interpretation

This is a negative transfer result. The direction-aware prompt is not a free inference-time improvement for a checkpoint trained on raw diff-only inputs. The model treats the new template as a distribution shift and collapses toward safe predictions at the default threshold.

The result does not disprove the direction-aware hypothesis. It narrows the next experiment: train a detector on the same direction-aware representation, then compare it against raw diff-only, localized, contrastive, and edge-focus `26+` results under the same bucket protocol.

## Next Step

Build a matched direction-aware training set from the existing paired diff train rows and train a small LoRA classifier on that representation. The key question is whether same-template training can use operation-direction labels to improve the hard `26+` bucket beyond the current edge-focus result of `0.7438` balanced accuracy.
