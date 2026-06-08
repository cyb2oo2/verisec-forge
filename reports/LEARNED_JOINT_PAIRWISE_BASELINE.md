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

## Explicit Pair-Head Ablation

An explicit MLP pair head was also trained over frozen detector representations, using a train-derived validation split for epoch selection and scoring the held-out `827` pairs only once.

| Frozen representation probe | Held-out orientation |
| --- | ---: |
| Hidden-state pair features | `0.6856` |
| Hidden state + detector score features | `0.6941` |

This ablation does not support the hypothesis that a more expressive head alone can replace pair-coupled decoding. The bottleneck is more likely representation adaptation and train/eval direction fidelity.

## Synthetic-Reversal Fidelity

The expanded `3,000`-pair training set uses observed directions plus synthetic reversals. On the real bidirectional eval pairs, a synthetic reversal matches the real reverse text exactly only `1.21%` of the time. Mean character similarity is high (`0.9278`), but the non-exact differences show that synthetic reversal should be treated as a consistency view, not equivalent gold supervision.

## Interpretation

This is a useful positive and negative result:

- Pair-level supervision and synthetic reversal materially improve orientation decisions.
- Independent threshold group-all-correct rises to `0.6155`.
- Joint decoding is exactly side-swap equivariant by construction.
- The remaining gap shows that a shared sequence classifier with a pairwise loss is not yet a stronger replacement for the calibrated pair-coupled system.

The reported `1.0` side-swap equivariance is enforced by the joint decision rule and must not be described as learned standalone invariance.

## Next Method Step

The next model should use real bidirectional pairs for supervised side choice and synthetic reversal only as a consistency regularizer. It should add:

1. real-pair supervised adaptation of the encoder and side-choice head
2. counterfactual consistency loss for metadata, formatting, identifiers, and non-security padding
3. evidence ranking only after side choice is stable
4. insufficient-context abstention after cleaner annotation targets exist

Raw report: `reports/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_report.json`
