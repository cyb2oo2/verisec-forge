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

## Transfer check: held-out nuisance transforms (unseen presentation changes)

The preregistration's second transfer leg -- held-out nuisance transforms never
seen during training or the original polarity-only-swap evaluation -- was still
outstanding after the CrossVul check above. Built five families on the
*identical* 600 PrimeVul/DeltaSecommits/PatchEval base pairs (verified
`pair_key` match to the original audit) via `src/vrf/nuisance_transfer.py` and
`scripts/build_nuisance_transfer_audit.py`:

- **context_window** -- unified diff with a tighter context budget (`n=1`
  instead of the `n=3` default used everywhere else).
- **split_view** -- the same removed/added content regrouped into separate
  "Removed" / "Added" / "Unchanged context" blocks instead of interleaved
  unified hunks.
- **diff_algorithm_myers_header** -- real `git diff --no-index` output
  (Myers algorithm, git's native header format: `diff --git`, `index`,
  `a/`/`b/` prefixes -- structurally different from the `difflib`-rendered
  header used everywhere else).
- **diff_algorithm_histogram** -- same git header family, `--diff-algorithm=histogram`.
- **whitespace_comment** -- reindented diff-body lines plus one inserted
  benign comment marker; code semantics and gold unchanged.

Reproduce:

```powershell
.\.venv\Scripts\python.exe scripts\build_nuisance_transfer_audit.py
.\.venv\Scripts\python.exe scripts\materialize_relational_runtime.py `
  --model-id qwen15b-nuisance-transfer-1024 `
  --tokenizer checkpoints\cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1 `
  --max-length 1024 --local-files-only `
  --benchmark data\processed\secure_code_nuisance_transfer_audit_v1.jsonl `
  --output data\processed\secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl
.\.venv\Scripts\python.exe scripts\predict_veripatch_rr.py `
  --checkpoint checkpoints\cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1 `
  --dataset data\processed\secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl `
  --output outputs\secure_code_nuisance_transfer_baseline_predictions_1024.jsonl --batch-size 4
.\.venv\Scripts\python.exe scripts\predict_veripatch_rr.py `
  --checkpoint checkpoints\cls_secure_code_primevul_repair_antisymmetric_qwen15b_lora_v1 `
  --dataset data\processed\secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl `
  --output outputs\secure_code_nuisance_transfer_repaired_predictions_1024.jsonl --batch-size 4
.\.venv\Scripts\python.exe scripts\analyze_nuisance_transfer.py
```

`transformation_introduced_critical_truncation_rows: 0` across all ten
(family × variant) conditions, n=600 pairs per family throughout.

| Family | null delta | fine-tuning delta | fixed | broken | McNemar p |
| --- | ---: | ---: | ---: | ---: | ---: |
| context_window | +0.058 | **+0.022** | 25 | 12 | 0.047 |
| split_view | +0.070 | **+0.033** | 42 | 22 | 0.017 |
| diff_algorithm_myers_header | +0.075 | **-0.017** | 15 | 25 | 0.154 |
| diff_algorithm_histogram | +0.067 | **-0.022** | 16 | 29 | 0.073 |
| whitespace_comment | +0.032 | +0.018 | 23 | 12 | 0.090 |
| *(reference)* PrimeVul in-distribution | +0.047 | +0.027 | 21 | 5 | 0.002 |
| *(reference)* CrossVul external-source | +0.017 | +0.009 | 6 | 3 | 0.508 |

**With five families tested, an uncorrected p<0.05 threshold is the wrong bar.**
At the Bonferroni-corrected threshold (p<0.05/5 = 0.010), **zero families
survive** -- the smallest observed p-value (split_view, 0.017) does not clear
it. Two families (`context_window`, `split_view`) show a positive delta at the
uncorrected p<0.05 level; two other families
(`diff_algorithm_myers_header`, `diff_algorithm_histogram`) show the
**fine-tuned model performing worse than the frozen baseline** under the
antisymmetric decision. A repair effect that reverses sign across held-out
presentation changes is itself evidence against a robust, content-based
transferable effect -- it looks like noise around a small, inconsistent
signal, not a repeatable gain that merely fell short of significance in two
conditions.

Side observation, not part of the transfer claim: under `split_view`, the
**independent-inference** side-swap violation rate jumps to 0.925 (both
models) -- far above its own marginal-conditioned baseline (~0.57-0.58) and
well above the ~0.55-0.66 range seen in the other four families. Restructuring
the same content into grouped removed/added blocks is dramatically more
disruptive to the un-repaired classifier's side-order consistency than any
other tested presentation change. This is a data point for future mechanism
work, not evidence for or against the fine-tuning transfer question (the
antisymmetric decision is exact-by-construction regardless of this).

Full per-family breakdown: `reports/secure_code_repair_antisymmetric_nuisance_transfer_v1.json`.

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

Establishes (held-out nuisance transforms, five families, n=600 each):

- The antisymmetric architecture's exactness (side-swap equivariance,
  violation rate 0 by construction) holds under every family tested,
  including presentations (git-native headers, split-view blocks) never seen
  in training.
- **The fine-tuning increment does not survive multiple-comparisons-corrected
  significance testing on any family**, and reverses sign (fine-tuned model
  worse than frozen baseline) on two of the five families.

Does **not** establish (required before any headline "repair works" claim):

- That fine-tuning is doing anything beyond the projection null. Neither
  transfer test (CrossVul, nuisance transforms) supports it.
- Generality: one seed (7), one config, one backbone, one length. The
  preregistered seed {7,123} × λ {0.5,1,2} grid was not swept.

## Honest one-line summary

The antisymmetric head makes side-order failure vanish by construction and
lifts canonical accuracy on PrimeVul from 0.660 to 0.733, but a matched control
shows most of that lift (+0.047 of +0.073) is the inference-time readout
applied to the *unchanged* model — the preregistered null — and only +0.027
(McNemar p = 0.002) is attributable to fine-tuning. That fine-tuning increment
does not transfer: on CrossVul (external source) it shrinks to +0.0086
(p = 0.508), and across five held-out nuisance-transform families it survives
no multiple-comparisons-corrected significance test and **reverses sign on two
of five families**. This run validates the antisymmetric readout as a
transferable structural fix for side-order inconsistency, but it does not
validate the fine-tuning objective as a learned repair. The fine-tuned
increment over the projection null is significant in-distribution but does not
survive either external-source or held-out nuisance-transform transfer
testing.
