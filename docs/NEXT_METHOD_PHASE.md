# Next Method Phase

The next research phase has three linked tracks.

## 1. Independent Human Patch-Pair Annotation

Build a `150`-pair high-value audit set with two independent blinded annotators. Record vulnerable side, root cause, minimal evidence lines, context sufficiency, confidence, and disagreement. Report exact agreement and Cohen's kappa, then adjudicate every disagreement.

Protocol: `docs/HUMAN_PATCH_PAIR_ANNOTATION_PROTOCOL.md`

Current local materialization:

- `827` candidate pair groups
- `150` selected pairs
- strata: model errors `32`, low margin `31`, high confidence `31`, large patch `25`, controls `31`

## 2. Counterfactual Shortcut Interventions

Measure causal sensitivity to nuisance changes rather than only correlational shortcut controls.

Protocol: `docs/COUNTERFACTUAL_SHORTCUT_PROTOCOL.md`

Reviewer-facing v2 materialization:

- `600` representative and `600` balanced-stress pair rows across three sources
- `1,200` base rows and `8,400` intervention rows
- tokenizer-neutral benchmark plus model-specific runtime accounting
- seeded representative sampling and explicit marginal stress quotas
- one canonical renderer for the base and true side-order swap
- occurrence-aware changed-line spans and runtime token visibility
- invariant, equivariant, and context-pressure results reported separately

Completed detector stress result:

- non-security padding changes `60.75%` of binary decisions and strongly biases predictions toward vulnerable
- format normalization changes `45.00%`
- metadata removal changes `31.75%`
- identifier normalization changes `30.75%`
- side-order swap violates the expected equivariant relation on `26.50%`

These v1 results remain useful diagnostics, but regex identifier normalization
and generic formatting normalization are not treated as validated
semantics-preserving transformations. V2 exposes the padding confound directly:
end padding introduces zero new critical-hunk truncations, while the same
numbered comments placed before the diff introduce truncation in `36/600`
pairs under the earlier Qwen/512 accounting. VeriPatch-RR v0.1 now requires
each model run to recompute this split with its own tokenizer and truncation
policy.

## 3. Learned Joint Secure Patch Model

Replace independent side scoring plus decoder-only coupling with a learned pair-level model that jointly predicts side choice, evidence ranking, calibrated confidence, and insufficient-context abstention.

Plan: `docs/LEARNED_JOINT_MODEL_PLAN.md`

Current learned baseline:

- `3,000` synthetic-complete train pairs from observed directions plus deterministic reversals
- `827` held-out real pair groups with zero train/eval pair overlap
- zero-shot warm start orientation accuracy `0.7074`
- `589`-pair joint training orientation accuracy `0.7606`
- expanded `3,000`-pair joint training orientation accuracy `0.8283`
- existing pair-coupled decoder remains stronger at five-split mean `0.8572`
- frozen explicit pair-head probes reach only `0.6856` to `0.6941`
- synthetic reverse is highly similar to real reverse (`0.9278` mean character similarity) but only `1.21%` exact
- real-only pairwise training reaches `0.7219`; synthetic consistency raises it to `0.7437`
- the consistency gain is paired-significant but small (`+0.0218`, McNemar `p=0.0474`)
- synthetic supervision remains stronger and more stable under the current counterfactual suite
- five pair-key calibration splits consistently select temperature `2.0` and abstention margin `0.075`
- selective accepted accuracy reaches `0.8767` at `0.7896` mean held-out coverage
- abstention captures `0.4087` of held-out orientation errors; this is a review route, not a full-coverage gain
- a 375-pair nuisance pilot cuts padding violation `0.4250 -> 0.1300` with paired `p<1.4e-23`
- the same pilot does not significantly change main-task orientation (`+0.0024`, `p=0.8450`)
- identifier improvement is suggestive but not significant (`+0.0275` relation success, `p=0.0708`)

## Research Gate

The side-choice-only joint baseline, selective calibration layer, and targeted nuisance pilot are now evaluated, but the learned model is not yet the strongest full-coverage method. Do not claim that selective accuracy replaces pair-coupled decoding. The immediate gate is to validate the frozen VeriPatch-RR v0.1 runtime contract on the existing 1.5B model, then run the same representative/stress protocol across model families.

- independent-side detector
- pair-coupled decoder
- human evidence subset
- counterfactual intervention benchmark
- external DeltaSecommits/PatchEval sources
