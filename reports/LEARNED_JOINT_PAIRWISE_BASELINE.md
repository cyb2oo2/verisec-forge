# Learned Joint Pairwise Baseline

## Result

The first learned pairwise side-choice model uses the existing 1.5B diff detector as a warm start and jointly optimizes:

- per-direction vulnerable/safe classification
- a vulnerable-over-safe pairwise margin
- complementary probabilities across the two directions

Training uses `3,000` observed PrimeVul directions plus deterministic synthetic reversals, producing `3,000` complete pair instances and `6,000` balanced directional examples. Evaluation uses `827` held-out real pair groups with zero train/eval `pair_key` overlap.

| Setting | Pair orientation / group all-correct |
| --- | ---: |
| Warm-start detector, no joint training | `0.7074` |
| Joint loss, 589 naturally complete train pairs | `0.7606` |
| Joint loss, 3,000 synthetic-complete train pairs | `0.8283` |
| Existing pair-coupled decoder, five-split mean | `0.8572` |

The expanded learned model improves over its zero-shot initialization by about `+0.1209`, but it does not beat the existing pair-coupled decoder.

## Interpretation

This is a useful positive and negative result:

- Pair-level supervision and synthetic reversal materially improve orientation decisions.
- Independent threshold group-all-correct rises to `0.6155`.
- Joint decoding is exactly side-swap equivariant by construction.
- The remaining gap shows that a shared sequence classifier with a pairwise loss is not yet a stronger replacement for the calibrated pair-coupled system.

The reported `1.0` side-swap equivariance is enforced by the joint decision rule and must not be described as learned standalone invariance.

## Next Method Step

The next model should use an explicit pair head over both directional representations rather than comparing two independently produced class probabilities. It should add:

1. a learned side-choice head over `[h(A->B), h(B->A), h(A->B)-h(B->A)]`
2. counterfactual consistency loss for metadata, formatting, identifiers, and non-security padding
3. evidence ranking only after side choice is stable
4. insufficient-context abstention after cleaner annotation targets exist

Raw report: `reports/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_report.json`
