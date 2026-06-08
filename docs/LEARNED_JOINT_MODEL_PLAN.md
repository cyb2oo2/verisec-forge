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

1. Train a lightweight lexical/cross-feature baseline to verify target health.
2. Train a 1.5B coder cross-encoder LoRA with side-choice loss only.
3. Add evidence-ranking loss.
4. Add confidence and insufficient-context losses only after human annotation provides cleaner targets.
5. Evaluate on held-out pair groups, external sources, and counterfactual interventions.

## Success Criteria

- Beats pair-coupled decoding on held-out pair groups or matches it while improving evidence grounding.
- Reduces side-wrong evidence collapse.
- Has lower invariant-intervention flip rate than the independent-side detector.
- Abstains on insufficient-context cases with high precision.

## Claim Boundary

Until trained and evaluated, this is a research plan and data protocol, not a performance result.
