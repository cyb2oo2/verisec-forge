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

Current local materialization:

- `200` pair groups
- `400` base rows
- `2400` intervention rows
- six intervention families with invariant, equivariant, or abstention-sensitive expectations

Completed detector stress result:

- non-security padding changes `60.75%` of binary decisions and strongly biases predictions toward vulnerable
- format normalization changes `45.00%`
- metadata removal changes `31.75%`
- identifier normalization changes `30.75%`
- side-order swap violates the expected equivariant relation on `26.50%`

These results make shortcut sensitivity an observed intervention effect rather than only a correlational concern.

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

## Research Gate

The side-choice-only joint baseline is now trained and evaluated, but it is not yet the strongest method. Do not claim that it replaces pair-coupled decoding. The next gate is an explicit pair-representation head evaluated against:

- independent-side detector
- pair-coupled decoder
- human evidence subset
- counterfactual intervention benchmark
- external DeltaSecommits/PatchEval sources
