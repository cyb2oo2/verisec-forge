# Learned Joint Secure Patch Reasoning Plan

## Motivation

Pair-coupled decoding is currently a strong system layer, but it is still a decoding rule over independently scored sides. The next method-level contribution should learn the coupled decision directly.

## Joint Targets

The joint model should predict:

- `side_choice`: which side is vulnerable
- `evidence_ranking`: which hunk/window supports that side choice
- `confidence`: calibrated probability for the side decision
- `insufficient_context`: whether the visible patch context is enough to decide

## Data Contract

Build the first dataset with:

```powershell
.\.venv\Scripts\python.exe scripts\build_joint_reasoning_dataset.py
```

The output records are pair-level examples with `side_a`, `side_b`, evidence candidates, target sources, and loss masks. Pseudo evidence labels are allowed for bootstrapping, but final claims require the human pair annotation protocol.

## First Training Ladder

1. Completed: train a 1.5B warm-start side-choice model with classification, pairwise margin, and complement losses.
2. Completed: expand from `589` naturally complete pairs to `3,000` synthetic-complete pairs.
3. Completed negative ablation: frozen explicit pair heads reach only `0.6856` with hidden features and `0.6941` with detector scores.
4. Completed diagnostic: synthetic reverse has `0.9278` mean character similarity to real reverse text but only `1.21%` exact matches.
5. Completed: real-only supervision reaches `0.7219`; adding synthetic consistency reaches `0.7437`.
6. Completed: paired McNemar confirms the small consistency gain (`+0.0218`, `p=0.0474`).
7. Completed: counterfactual comparison favors synthetic supervision overall (`0.2494` vs `0.2944` mean invariant change).
8. Completed: five pair-key splits select the same temperature (`2.0`) and abstention margin (`0.075`).
9. Completed: at `0.7896` mean held-out coverage, accepted accuracy reaches `0.8767` and abstention captures `0.4087` of errors.
10. Next: add targeted nuisance consistency only for the interventions that remain weak.
11. Add evidence-ranking loss only after side choice is stable.
12. Add confidence and insufficient-context losses only after cleaner annotation targets exist.
13. Evaluate on held-out pair groups, external sources, and counterfactual interventions.

## Success Criteria

- Beats pair-coupled decoding on held-out pair groups or matches it while improving evidence grounding.
- Reduces side-wrong evidence collapse.
- Has lower invariant-intervention flip rate than the independent-side detector.
- Abstains on insufficient-context cases with high precision.

## Claim Boundary

The first side-choice-only learned baseline reaches `0.8283` orientation accuracy on `827` held-out pairs, improving over its `0.7074` zero-shot warm start but remaining below the existing pair-coupled decoder (`0.8572` five-split mean). Selective calibration raises accepted-pair accuracy to `0.8767` at `0.7896` coverage, but this conditional metric is not a full-coverage replacement claim.
