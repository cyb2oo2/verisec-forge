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
3. Next: replace independent directional probabilities with an explicit learned pair-representation head.
4. Add counterfactual consistency loss before adding evidence ranking.
5. Add evidence-ranking loss only after side choice is stable.
6. Add confidence and insufficient-context losses only after cleaner annotation targets exist.
7. Evaluate on held-out pair groups, external sources, and counterfactual interventions.

## Success Criteria

- Beats pair-coupled decoding on held-out pair groups or matches it while improving evidence grounding.
- Reduces side-wrong evidence collapse.
- Has lower invariant-intervention flip rate than the independent-side detector.
- Abstains on insufficient-context cases with high precision.

## Claim Boundary

The first side-choice-only learned baseline reaches `0.8283` orientation accuracy on `827` held-out pairs, improving over its `0.7074` zero-shot warm start but remaining below the existing pair-coupled decoder (`0.8572` five-split mean). This supports the learning direction but not a replacement claim.
