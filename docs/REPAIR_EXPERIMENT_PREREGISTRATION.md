# Repair Experiment Preregistration

Locks the conditions, decision rules, and success criteria for the repair run
**before** the repaired model exists, so the result cannot be tuned into
significance after the fact. Architecture and objective: see
`docs/REPAIR_OBJECTIVE_DESIGN.md`. Evaluation contract: implemented in
`src/vrf/repair_evaluation.py` and run by `scripts/evaluate_repair_criteria.py`
— the *same* code scores the baseline and the repaired model.

## Pre-repair baseline (measured now, un-repaired checkpoint)

`scripts/evaluate_repair_criteria.py` on the existing polarity-audit predictions
(`checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1`, len 1024,
600 pairs) → `reports/secure_code_repair_criteria_pre_repair_baseline_v1.json`:

| Metric | Value |
| --- | ---: |
| canonical accuracy | 0.660 |
| polarity-only accuracy (gold fixed) | 0.345 |
| side-swap accuracy | 0.665 |
| polarity flip rate (target ≤ 0.05) | **0.508** |
| polarity probability gap | 0.428 |
| relation violation rate | **0.510** |
| relation-stratified marginal-conditioned violation baseline | 0.494 |
| canonical model A-rate (target 0.4–0.6) | 0.613 |

**The current model fails every applicable relational criterion.** Its violation
rate (0.510) is *above* the relation-stratified marginal-independence floor
(0.494) — i.e. no
better than two independent classifiers — and it flips on ~51% of pairs when the
diff is re-rendered with gold held fixed. This is the bar the repair must clear.

## Fixed experimental conditions

- **Base data / checkpoint:** the same joint side-choice training data
  (`secure_code_primevul_joint_side_choice_train_v1.jsonl`, already
  orientation-balanced 3000/3000) and the same Qwen2.5-Coder-1.5B backbone, so
  the only change is the head + objective.
- **Head:** `AntisymmetricPairHead` (`antisymmetric_pair_head_torch.py`) over the
  shared encoder's pooled feature for both candidate orderings.
- **Objective:** `repair_loss_torch` = pointwise BCE + λ·polarity-invariance +
  0.1·collapse-guard. Grid `λ ∈ {0.5, 1.0, 2.0}`; pick λ on the *validation*
  polarity-invariance vs canonical-accuracy trade-off, not on test.
- **Seeds:** train seeds {7, 123}; report both. No seed selection post-hoc.
- **Length:** 1024, matching the baseline.
- **Evaluation set:** the held-out 600-pair polarity audit
  (`canonical` / `polarity_only_swap` / `side_swap`), plus the transfer sets
  below.

## Baselines run alongside (all on identical eval rows)

1. **Both-orientation augmentation** (already in the training data) — same
   backbone/head-free trainer. The repair must beat this **on transfer**, not
   in-distribution.
2. **Test-time symmetrization (TTA)** on the un-repaired model — the null for
   "did the representation change?".
3. **Independent-scoring ablation** `s = f(A) − f(B)` — antisymmetric but no
   cross-candidate interaction; shows the interaction's worth.
4. **Unconstrained head + soft equivariance penalty** — shows the hard
   constraint matters.
5. **Constant / majority predictor** — the degeneracy floor.

## Success criteria (all must hold; raw single-pass predictions only)

Judged by `evaluate_repair_criteria` with `--baseline-canonical-accuracy 0.66`:

1. `canonical_non_inferiority`: canonical accuracy delta ≥ −0.02 vs baseline.
2. `polarity_invariance`: polarity flip rate ≤ 0.05 (from 0.508) and the
   probability gap shrinks.
3. `violation_below_baseline`: raw violation rate **strictly below** its
   relation-stratified marginal-conditioned baseline (from 0.510 > 0.494 to
   clearly below).
4. `no_degeneracy`: canonical A-rate ∈ [0.4, 0.6]; per-class accuracy balanced.
5. **Transfer (reported separately, required for the headline claim):** criteria
   2–4 also hold on nuisance transforms *not trained on* (diff context size,
   unified vs split, Myers vs histogram, whitespace/comment reorder) and on the
   **CrossVul relational subset**.

A run that passes 1–4 in-distribution but fails transfer is reported as
"regularized to the trained transforms," **not** a repair.

## Transfer criterion 5 status (both legs now run; see `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`)

Both halves of criterion 5 have been executed against the v1 antisymmetric
repair from `docs/REPAIR_EXPERIMENT_PREREGISTRATION.md`'s runbook:

- **CrossVul relational subset (external source, n=350):** the fine-tuning
  delta over the projection null shrinks from +0.0267 (p=0.002) in-distribution
  to +0.0086 (p=0.508) — not significant.
- **Held-out nuisance transforms (five families, n=600 each):** context window,
  split view, git-native Myers/histogram diff, and whitespace/comment
  perturbation (`src/vrf/nuisance_transfer.py`,
  `scripts/build_nuisance_transfer_audit.py`,
  `scripts/analyze_nuisance_transfer.py`). No family survives a
  Bonferroni-corrected significance threshold (p<0.01 for five families
  tested); two families show the fine-tuned model performing *worse* than the
  frozen baseline.

**Criterion 5 fails.** Per this document's own rule, the result is "regularized
to the trained transforms," not a repair: the antisymmetric-readout
architecture is validated as a transferable structural fix (its by-construction
guarantees hold on every tested condition), but the fine-tuning objective is
**not** validated as a transferable learned repair.

## What will NOT count as success

- Any metric computed with test-time symmetrization or the relation-consistent
  decoder in the path (those are separate, labeled rows — see
  `docs/EVIDENCE_HIERARCHY.md`).
- A violation-rate drop accompanied by A-rate drifting outside [0.4, 0.6] or a
  canonical-accuracy regression beyond the non-inferiority margin.
- Improvement only on the exact transforms in the training loss.

## Runbook (GPU; user-driven)

Training is a GPU run and is **not** executed as part of this preregistration.
Mind the VRAM note: batch-8 at length 1024 thrashes 12 GB; use batch 2–4 or
`--resume`.

```powershell
# 1. Train the repaired head (to be wired into the joint-pairwise trainer)
.\.venv\Scripts\python.exe scripts\train_joint_pairwise_classifier.py `
  --config configs\research_primevul_joint_pairwise_repair_antisymmetric_v1.json

# 2. Materialize + predict on the polarity audit (existing pipeline)
#    -> outputs\...repair_antisymmetric...predictions_1024.jsonl

# 3. Score against the locked criteria
.\.venv\Scripts\python.exe scripts\evaluate_repair_criteria.py `
  --predictions outputs\...repair_antisymmetric...predictions_1024.jsonl `
  --baseline-canonical-accuracy 0.66 `
  --label repaired_antisymmetric_v1 `
  --output reports\secure_code_repair_criteria_repaired_antisymmetric_v1.json
```

Report the repaired result next to the pre-repair baseline in the same table;
promote to a headline claim only if the transfer criteria also pass.
