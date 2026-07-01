# Repair Result: One Antisymmetric-Head Run (v1)

The single preregistered repair run from
`docs/REPAIR_EXPERIMENT_PREREGISTRATION.md` (one config: seed 7, antisymmetric
head, 3000 training pairs, len 1024). Evaluated on the held-out 600-pair
polarity audit with the locked criteria (`scripts/evaluate_repair_criteria.py`).
Reproduce:

```powershell
.\.venv\Scripts\python.exe scripts\train_antisymmetric_repair.py `
  --config configs\research_primevul_joint_pairwise_repair_antisymmetric_v1.json
.\.venv\Scripts\python.exe scripts\predict_veripatch_rr.py `
  --checkpoint checkpoints\cls_secure_code_primevul_repair_antisymmetric_qwen15b_lora_v1 `
  --dataset data\processed\secure_code_qwen_mechanism_polarity_only_swap_audit_v1_runtime1024.jsonl `
  --output outputs\secure_code_repair_antisymmetric_polarity_audit_predictions_1024.jsonl --batch-size 4
```

## Headline table (raw single-pass, canonical accuracy)

| Model / inference | canonical | polarity-only | polarity flip rate | violation rate | A-rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline, independent inference (pre-repair) | 0.660 | 0.345 | 0.508 | 0.510 | 0.613 |
| Repaired, independent inference | 0.662 | 0.345 | 0.487 | 0.489 | 0.668 |
| **Baseline, antisymmetric inference (NULL)** | **0.707** | 0.707* | 0.000* | 0.000* | — |
| **Repaired, antisymmetric inference** | **0.733** | 0.733* | 0.000* | 0.000* | 0.467 |

`*` polarity-invariance, swap-equivariance, flip rate, and violation rate are
**exact by construction** of the antisymmetric readout, not emergent. The only
empirical quantity is canonical accuracy.

## The decomposition that matters

The repaired model passes all four in-distribution criteria. But the honest
attribution — from the preregistered baselines — is:

- **Antisymmetric fine-tuning alone did essentially nothing to the independent
  classifier.** Independent-inference polarity-only accuracy is unchanged
  (0.345 → 0.345) and flip rate barely moves (0.508 → 0.487). The repair does
  **not** live in the per-rendering readout.
- **The antisymmetric *inference* readout recovers most of the accuracy — even
  on the frozen, un-repaired model:** 0.660 → **0.707** (+0.047). This is the
  preregistration's **test-time-symmetrization null**: a structural projection,
  not trained improvement. It cannot be counted as a learned repair.
- **Fine-tuning adds a small but significant increment on top:** antisymmetric
  inference 0.707 (baseline) → **0.733** (repaired), +0.027, exact McNemar
  **p = 0.002** (21 pairs fixed, 5 broken, n = 600).

So of the visible 0.660 → 0.733 gain, ~+0.047 is the architecture/projection
(the null) and ~+0.027 is the trained contribution.

## What this does and does not establish

Establishes (in-distribution, one checkpoint, one length, 600 pairs):

- The antisymmetric architecture removes the polarity/side-order failure by
  construction and holds canonical non-inferiority (it improves it).
- Fine-tuning with the antisymmetric objective adds a small, statistically
  significant canonical-accuracy gain over the projection null.

Does **not** establish (required before any headline "repair works" claim):

- **Transfer.** The preregistered transfer criteria — held-out nuisance
  transforms (context size, unified vs split, Myers vs histogram, whitespace)
  and the CrossVul relational subset — were **not** run. Everything here is
  in-distribution on the polarity audit.
- That the gain is not mostly projection. By the project's own evidence rules,
  the +0.047 antisymmetric-inference-on-baseline is the null; the defensible
  trained effect is the +0.027, which is small.
- Generality: one seed (7), one λ-implicit config, one backbone, one length. The
  preregistered seed {7,123} × λ {0.5,1,2} grid was not swept ("exactly one
  run").

## Honest one-line summary

The antisymmetric head makes side-order failure vanish by construction and lifts
canonical accuracy to 0.733, but a matched control shows most of that lift
(+0.047 of +0.073) is the inference-time readout applied to the *unchanged*
model — the preregistered null — and only +0.027 (McNemar p = 0.002) is
attributable to the fine-tuning. This is a promising in-distribution signal, not
a validated repair: transfer to held-out nuisance transforms and CrossVul
remains the gate.
