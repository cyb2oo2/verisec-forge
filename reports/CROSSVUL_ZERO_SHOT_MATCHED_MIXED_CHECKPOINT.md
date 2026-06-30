# CrossVul Open-Set Zero-Shot: Matched-Mixed vs. Single-Source Checkpoint

This report compares two checkpoints, both zero-shot on the same CrossVul
C/C++ paired-diff eval set built in
`reports/CROSSVUL_PAIR_DIFF_DATASET.md`, to test whether broader-source
training generalizes better to a genuinely unseen fourth source than
single-source training -- neither checkpoint has ever seen CrossVul.

## Protocol

- Source dataset: `crossvul (data/raw/crossvul_train_raw.jsonl, c/cpp only)`
- Checkpoint A (single-source): `cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1`
  (PrimeVul only; see `reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md`)
- Checkpoint B (matched-mixed): `cls_secure_code_matched_mixed_primevul_time_short_deltasecommits_qwen15bcoder_lora_pair_diff_v1`
  (PrimeVul + DeltaSecommits) -- the same "single matched-mixed checkpoint"
  baseline that `reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md` compares the
  learned router against
- Threshold: `0.5`
- Pair-coupling margin: `0.02`
- Rows: `8742` (`4371` pair groups, `4371` safe / `4371` vulnerable)

## Results

| Checkpoint | System | BA | Recall | Specificity | Group All-Correct | Orientation |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Single-source (PrimeVul only) | default threshold | `0.7793` | `0.7470` | `0.8117` | `0.6731` | `0.8076` |
| Single-source (PrimeVul only) | pair-coupled | `0.8061` | `0.8014` | `0.8108` | `0.7881` | `0.8076` |
| Matched-mixed (PrimeVul + DeltaSecommits) | default threshold | `0.8115` | `0.7966` | `0.8264` | `0.7504` | `0.8167` |
| Matched-mixed (PrimeVul + DeltaSecommits) | pair-coupled | `0.8141` | `0.8129` | `0.8154` | `0.8026` | `0.8167` |

| Delta (matched-mixed minus single-source) | default threshold | pair-coupled |
| --- | ---: | ---: |
| BA | `+0.0322` | `+0.0080` |
| Group all-correct | `+0.0773` | `+0.0145` |
| Orientation | `+0.0091` | `+0.0091` |

## Interpretation

The matched-mixed checkpoint outperforms the single-source checkpoint on this
genuinely unseen fourth source at every metric, in both the default-threshold
and pair-coupled settings. The gap is largest at default threshold
(`+0.0322` BA, `+0.0773` group all-correct) and narrows substantially once
pair-coupling is applied (`+0.0080` BA), consistent with this project's
existing finding that pair-coupling recovers much of what a single-threshold
detector loses under distribution shift -- here it narrows the gap between
two *different* checkpoints, not just between threshold and pair-coupled
predictions from one checkpoint.

This is consistent with, and extends, the router's own closed-world finding
(`reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`): broader-source training helps
generalization. The router showed this for closed-world routing among known
sources; this result shows the same direction holds even on a source neither
checkpoint has seen at all. It does not show that routing itself would help
on CrossVul -- that would require the full leave-one-source router
machinery, not run here -- only that the underlying mixed-source checkpoint
the router routes among is itself more robust than a single-source
checkpoint to begin with.

## Claim Boundary

This is a two-checkpoint, single-threshold, single-margin comparison on one
C/C++-only eval set. It does not establish that mixed-source training
generalizes better in general, only that it does on this comparison. It does
not test whether the learned content-source router itself would improve
further on CrossVul, and it does not include PatchEval in the mixed
checkpoint's training sources (this matched-mixed checkpoint is PrimeVul +
DeltaSecommits only, matching the router's existing baseline comparison
point, not a three-source mixture).
