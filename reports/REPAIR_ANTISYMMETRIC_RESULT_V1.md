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

## Transfer check: CrossVul relational subset (unseen source)

The in-distribution result above cannot be trusted on its own — the
preregistration requires it survive on a source neither the base classifier nor
the repair fine-tune ever saw. Built a 350-pair CrossVul canonical /
polarity-only-swap / side-swap audit by pointing the existing benchmark and
audit builders at CrossVul (`build_relational_benchmark_v2.py --source
crossvul=...` then `build_qwen_mechanism_polarity_only_swap_audit.py`, no new
transform logic), materialized runtime for length 1024
(`transformation_introduced_critical_truncation_rows: 0`), and ran both
checkpoints. Reproduce:

```powershell
.\.venv\Scripts\python.exe scripts\build_relational_benchmark_v2.py `
  --source crossvul=data\processed\secure_code_crossvul_pair_diff_eval_metadata.jsonl `
  --pairs-per-source 350 `
  --output data\processed\secure_code_crossvul_relational_benchmark_v2.jsonl
.\.venv\Scripts\python.exe scripts\build_qwen_mechanism_polarity_only_swap_audit.py `
  --benchmark data\processed\secure_code_crossvul_relational_benchmark_v2.jsonl `
  --output data\processed\secure_code_crossvul_polarity_only_swap_audit_v1.jsonl
.\.venv\Scripts\python.exe scripts\materialize_relational_runtime.py `
  --model-id qwen15b-crossvul-transfer-1024 `
  --tokenizer checkpoints\cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1 `
  --max-length 1024 --local-files-only `
  --benchmark data\processed\secure_code_crossvul_polarity_only_swap_audit_v1.jsonl `
  --output data\processed\secure_code_crossvul_polarity_only_swap_audit_v1_runtime1024.jsonl
```

| Model / inference | canonical (CrossVul) | polarity-only | flip rate | violation |
| --- | ---: | ---: | ---: | ---: |
| Baseline, independent | 0.786 | 0.251 | 0.740 | 0.504 |
| Repaired, independent | 0.794 | 0.251 | 0.709 | 0.490 |
| **Baseline, antisymmetric inference (NULL)** | **0.803** | 0.803* | 0.000* | 0.000* |
| **Repaired, antisymmetric inference** | **0.811** | 0.811* | 0.000* | 0.000* |

`*` exact by construction, as before. n = 350 pairs, exact McNemar on the
antisymmetric-inference canonical decision:

| Comparison | delta | fixed | broken | exact McNemar p |
| --- | ---: | ---: | ---: | ---: |
| PrimeVul (in-distribution, n=600) | **+0.0267** | 21 | 5 | **0.002** |
| CrossVul (unseen source, n=350) | **+0.0086** | 6 | 3 | **0.508** |

**The trained effect does not clearly survive on CrossVul.** On the unseen
source, fine-tuning changes only 3 net pairs out of 350 — indistinguishable
from chance flips. The projection null itself replicates directionally
(independent → antisymmetric inference: +0.017 on CrossVul vs +0.047 on
PrimeVul, both positive), consistent with it being architectural rather than
data-dependent, as expected. But the one number the preregistration was built
to gate — whether *training* the antisymmetric objective adds a real,
transferable effect — comes back **not significant** on held-out data.

Side note, not a transfer claim: raw canonical accuracy is far higher on
CrossVul (~0.79) than PrimeVul (~0.66) for both models, and CrossVul's baseline
polarity flip rate (0.740) is *worse* than PrimeVul's (0.508). This is
consistent with `docs/TASK_FORMULATION.md` and `reports/POLARITY_GOLD_CONFOUND.md`:
CrossVul's net-polarity/gold correlation may simply be stronger, inflating
canonical accuracy for the same shortcut reason it does on PrimeVul, not because
the model reasons better on an unseen source. This was not separately measured
here and should be checked before citing the CrossVul accuracy numbers on their
own.

## What this does and does not establish

Establishes (PrimeVul, in-distribution, one checkpoint, one length, n=600):

- The antisymmetric architecture removes the polarity/side-order failure by
  construction and holds canonical non-inferiority (it improves it).
- Fine-tuning with the antisymmetric objective adds a small, statistically
  significant canonical-accuracy gain over the projection null in-distribution.

Establishes (CrossVul, unseen source, n=350):

- The antisymmetric-inference architecture (the null) transfers: canonical
  accuracy and by-construction invariance both hold on CrossVul.
- **The fine-tuned increment over the null does not transfer**: +0.0086,
  p = 0.508 — not distinguishable from noise.

Does **not** establish (required before any headline "repair works" claim):

- That fine-tuning is doing anything beyond the projection null. The one
  transfer test run says no.
- The held-out **nuisance-transform** leg of the preregistration (context size,
  unified vs split, Myers vs histogram, whitespace/comment reorder) — still not
  run; only the external-source leg was completed here.
- Generality: one seed (7), one config, one backbone, one length. The
  preregistered seed {7,123} × λ {0.5,1,2} grid was not swept.

## Honest one-line summary

The antisymmetric head makes side-order failure vanish by construction and
lifts canonical accuracy on PrimeVul from 0.660 to 0.733, but a matched control
shows most of that lift (+0.047 of +0.073) is the inference-time readout
applied to the *unchanged* model — the preregistered null — and only +0.027
(McNemar p = 0.002) is attributable to fine-tuning. Run on CrossVul (an unseen
source, the preregistration's external-source transfer test), the architectural
null replicates (+0.017) but **the fine-tuned increment shrinks to +0.0086 and
loses significance (p = 0.508)**. Verdict: the antisymmetric-readout
architecture is a real, transferable structural fix for side-order
inconsistency; the additional training signal on top of it is not yet
demonstrated to generalize and should not be reported as a validated repair.
