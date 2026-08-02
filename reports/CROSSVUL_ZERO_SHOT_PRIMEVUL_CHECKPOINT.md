# CrossVul Open-Set Zero-Shot Transfer Evaluation

> **HISTORICAL DOCUMENT — CONTAINS WITHDRAWN RESULTS.**
> Contains results or interpretations withdrawn after adversarial structural-control
> analysis. Under the closed-world pair constraint the detector reaches `0.8596` balanced
> accuracy and a semantics-free character-level diff control reaches `0.8588` on the same
> population; the difference (`+0.0008`, clustered 95% CI `[-0.0202, +0.0222]`, sign test
> 19 vs 18, `p=1.0`) is not distinguishable from zero.
> **Do not cite as the repository's current scientific conclusion.**
> Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).


This report evaluates the headline PrimeVul-trained paired-diff detector directly on
CrossVul C/C++ paired vulnerable/secure snapshots -- a source this checkpoint has never
seen in training, development, or model selection. PrimeVul, DeltaSecommits, and
PatchEval are the project's three existing sources; CrossVul is a genuine fourth, isolating
open-set source shift from the closed-world routing already characterized in
`reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`.

## Protocol

- Source dataset: `crossvul (data/raw/crossvul_train_raw.jsonl, c/cpp only)`
- Checkpoint: `checkpoints/cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `8742`
- Pair groups: `4371`
- Safe/vulnerable: `4371/4371`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.7793` | `0.747` | `0.8117` | `0.7987` | `0.772` | `0.6731` | `0.8076` |
| `pair-coupled` | `0.8061` | `0.8014` | `0.8108` | `0.809` | `0.8052` | `0.7881` | `0.8076` |

## Interpretation

This is the project's first genuine open-set source-shift check: CrossVul was not used
anywhere in this checkpoint's training, development, or model selection, unlike the
closed-world router stress tests in `reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`.

Pair-coupled BA `0.8061` is well above chance and not far below the PrimeVul paired-diff
mainline (`0.8287`, three-seed mean), but it is meaningfully below the DeltaSecommits
(`0.8641` pair-coupled) and PatchEval zero-shot transfer numbers. This is a real, bounded
degradation, not a collapse: the paired-diff formulation carries signal onto a source it has
never seen, but DeltaSecommits and PatchEval may be more similar in commit style, diff
shape, or CWE distribution to PrimeVul than CrossVul is -- "external" does not uniformly mean
"equally far" from the training distribution. Group all-correct rate also drops further at
default threshold (`0.6731`) than pair-coupled (`0.7881`), consistent with the project's
existing finding that pair-coupling recovers some of the gap a single-threshold detector
loses under distribution shift.

## Claim Boundary

This is a single zero-shot transfer check on one checkpoint, one threshold, one pair-coupling
margin, restricted to C/C++ to isolate source shift from language shift. It does not
establish that the paired-diff formulation generalizes to arbitrary new sources, and it does
not test CrossVul's many other languages (PHP, JavaScript, Python, Java, ...), which remains
a separate, not-yet-run language-shift stress test. It is evidence that closes part of
`docs/NEXT_PHASE_ROADMAP.md`'s "Current Gaps" item 1 (open-set source shift), not a complete
answer to it.
