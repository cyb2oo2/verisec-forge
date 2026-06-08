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

## 3. Learned Joint Secure Patch Model

Replace independent side scoring plus decoder-only coupling with a learned pair-level model that jointly predicts side choice, evidence ranking, calibrated confidence, and insufficient-context abstention.

Plan: `docs/LEARNED_JOINT_MODEL_PLAN.md`

Current local materialization:

- `827` pair-level records
- deterministic hash-randomized side order
- side targets balanced at `414 A / 413 B`
- confidence/abstention masks available for `574` weakly labeled records

## Research Gate

Do not claim the joint model as a result until it is trained on pair-group-disjoint data and evaluated against:

- independent-side detector
- pair-coupled decoder
- human evidence subset
- counterfactual intervention benchmark
- external DeltaSecommits/PatchEval sources
