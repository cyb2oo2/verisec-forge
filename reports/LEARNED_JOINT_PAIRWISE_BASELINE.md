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

## Real-Pair And Consistency Ablation

Reconstructing `3,772` real bidirectional train pairs and excluding all held-out source pair keys does not by itself improve the learned model:

| Supervision | Held-out orientation |
| --- | ---: |
| Real bidirectional only | `0.7219` |
| Real bidirectional + synthetic consistency | `0.7437` |
| Synthetic reverse as direct supervision | `0.8283` |

The consistency model repairs `46` real-only mistakes and introduces `28` new mistakes (`+0.0218`, exact McNemar `p=0.0474`). The gain is real but small. Synthetic supervision remains substantially stronger (`p<1.3e-8` versus consistency).

Counterfactual stress does not show a hidden robustness win for the consistency model. At the same 768-token inference cap, synthetic supervision has higher base accuracy (`0.8225` vs `0.7900`), lower mean invariant change (`0.2494` vs `0.2944`), and lower side-order violation (`0.2250` vs `0.3125`).

## Validation-Selected Selective Calibration

The stronger synthetic-supervised checkpoint was calibrated over five pair-key-disjoint calibration/evaluation splits. The direction rule remains unchanged: only temperature and a low-margin abstention route are selected.

All five splits independently select temperature `2.0` and raw probability-gap margin `0.075`. On held-out pair groups:

| Metric | Five-split mean |
| --- | ---: |
| Full-coverage orientation accuracy | `0.8352` |
| Selective coverage | `0.7896` |
| Accepted-pair accuracy | `0.8767` |
| Errors captured by abstention | `0.4087` |
| Raw / calibrated ECE | `0.1017` / `0.0780` |
| Raw / calibrated NLL | `0.4629` / `0.4236` |

Brier score is effectively unchanged (`0.1353` to `0.1354`), so this is not evidence of uniformly better probability calibration. It is evidence that pair margin is useful for a review/abstention operating point.

A non-zero direction threshold is deliberately not tuned: the stored evaluation predictions are aligned by target class, so tuning a directional offset would leak gold ordering. The valid deployment-facing operation is to preserve the swap-equivariant direction comparison and route low-margin pairs for review.

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

Validation-selected selective calibration is now complete. The next training step should preserve the stronger synthetic-supervised checkpoint and add:

1. targeted consistency for non-security padding and identifier normalization rather than a uniform reverse-view loss
2. evaluation of the calibrated abstention route on external paired-patch sources
3. evidence ranking only after side choice is stable
4. insufficient-context supervision after cleaner annotation targets exist

Raw report: `reports/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_report.json`

Selective calibration: `reports/PRIMEVUL_JOINT_PAIRWISE_SELECTIVE_CALIBRATION.md`
