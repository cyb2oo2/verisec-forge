# CrossVul Multi-Language Zero-Shot Transfer Evaluation (Single-Source Checkpoint)

This is the raw protocol/results record for the single-source checkpoint half of the
language-shift comparison in `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md`. Read that
report for the comparison against the C/C++-only CrossVul result and the per-language
breakdown; this file only records the protocol and headline numbers for this run.

## Protocol

- Source dataset: `crossvul (data/raw/crossvul_train_raw.jsonl, php/javascript/python/java only)`
- Checkpoint: `checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `7560`
- Pair groups: `3780`
- Safe/vulnerable: `3780/3780`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.7589` | `0.7672` | `0.7505` | `0.7546` | `0.7609` | `0.6201` | `0.8114` |
| `pair-coupled` | `0.8132` | `0.8175` | `0.809` | `0.8106` | `0.814` | `0.7902` | `0.8114` |

## Interpretation

See `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md` for the comparison against the C/C++
CrossVul subset, the per-language breakdown, and the claim boundary.
