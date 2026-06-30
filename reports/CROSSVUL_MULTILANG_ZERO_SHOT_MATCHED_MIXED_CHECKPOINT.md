# CrossVul Multi-Language Zero-Shot Transfer Evaluation (Matched-Mixed Checkpoint)

This is the raw protocol/results record for the matched-mixed checkpoint half of the
language-shift comparison in `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md`. Read that
report for the comparison against the C/C++-only CrossVul result and the per-language
breakdown; this file only records the protocol and headline numbers for this run.

## Protocol

- Source dataset: `crossvul (data/raw/crossvul_train_raw.jsonl, php/javascript/python/java only)`
- Checkpoint: `checkpoints/cls_secure_code_matched_mixed_primevul_time_short_deltasecommits_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `7560`
- Pair groups: `3780`
- Safe/vulnerable: `3780/3780`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.818` | `0.7825` | `0.8534` | `0.8423` | `0.8113` | `0.7426` | `0.8341` |
| `pair-coupled` | `0.8316` | `0.8198` | `0.8434` | `0.8396` | `0.8296` | `0.8124` | `0.8341` |

## Interpretation

See `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md` for the comparison against the C/C++
CrossVul subset, the per-language breakdown, and the claim boundary.
