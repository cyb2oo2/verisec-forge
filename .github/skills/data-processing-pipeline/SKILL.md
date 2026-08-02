---
name: data-processing-pipeline
description: >-
  Build reproducible, auditable data cleaning and preprocessing steps that emit
  hashed manifests. Use when materializing datasets, rendering paired diffs,
  tokenizing/truncating for a specific model, deduping, splitting, or writing a
  JSONL artifact. Triggers: dataset, preprocess, clean, tokenize, materialize,
  split, dedup, manifest, JSONL, data hygiene, leakage, PrimeVul, CrossVul.
---

# Data Processing Pipeline

Turn raw sources (PrimeVul, CrossVul, DeltaSecommits, PatchEval) into
model-ready artifacts **without introducing leakage, shortcut confounds, or
untracked transformations.** In this project the data pipeline is a primary
source of scientific risk (polarity/gold confounds, side-swap rendering), so
reproducibility and de-confounding are the whole point.

## When to Use

- Materializing or rebuilding a dataset artifact under `data/processed/`.
- Rendering paired vulnerable/fixed diffs, side swaps, or counterfactuals.
- Tokenizing/truncating against a specific model's own tokenizer + context length.
- Splitting (held-out / time- / CVE- / project-disjoint) or deduping.
- Emitting or checking a SHA256 manifest for a data artifact.

## Instructions

### 1. Treat inputs as immutable text
- Vulnerability samples are **text for measurement, not code to execute**. Never
  run sample code; never let a sample path escape its intended directory.
- Read raw data from `data/raw/` read-only; write derived artifacts elsewhere.

### 2. Make every transform explicit and ordered
- One function per transform in `src/vrf/`; the script composes them in a fixed
  order. No hidden global state, no in-place mutation of raw inputs.
- Deterministic ordering + fixed seeds for any sampling/shuffling/splitting.

### 3. Guard against the project's known confounds
- **Polarity/gold confound:** ensure rendering orientation is de-confounded from
  the gold label (train + eval), and log net-polarity as a *tracked nuisance*,
  not a silent feature. See `docs/TASK_FORMULATION.md`,
  `reports/POLARITY_GOLD_CONFOUND.md`.
- **Side-swap rendering:** render swaps through one canonical path; track changed
  lines via exact fast-tokenizer offsets.
- **Truncation:** compute truncation with each model's own tokenizer, context
  length, truncation side, and special-token policy. Never assume 512.

### 4. Prevent leakage across splits
- Split by the disjointness axis you claim (CVE / project / time). Verify no
  shared identifier crosses the boundary before writing.

### 5. Emit a manifest
- Write JSONL artifacts, then generate/refresh a SHA256 manifest via
  `scripts/build_reproducibility_bundle.py`. Store manifests under
  `reproducibility/`. A pipeline output with no manifest is not releasable.

### 6. Validate
- Re-run with `--check-only` to confirm hashes match. Add a row-count / class-
  balance / de-confound assertion (e.g. `3000/3000` forward/reverse) to the log.

## Best Practices & Guardrails

- **Do** log row counts, class balance, and de-confound stats for every output.
- **Do** keep raw → processed traceable (record source file + commit).
- **Don't** execute or import sample vulnerability code.
- **Don't** overwrite a checked-in artifact without refreshing its manifest.
- **Don't** silently drop rows; log every filter and how many it removed.

## Examples

**Materialize a model-specific runtime (from README)**
```powershell
.\.venv\Scripts\python.exe scripts\materialize_relational_runtime.py `
  --model-id <model-id> `
  --tokenizer <tokenizer-id-or-path> `
  --max-length 512 `
  --output data\processed\<model>-veripatch-rr-runtime.jsonl
```

**Manifest check**
```powershell
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only --include-generated
```

## Dependencies / Tools

- `src/vrf/` (io_utils, counterfactuals, relational_benchmark), `scripts/build_*`, `scripts/materialize_*`
- `datasets` (via `.[train]`), the target model's tokenizer (`transformers`)
- `reproducibility/` manifests; `scripts/build_reproducibility_bundle.py`
- Related skills: [[reproducibility-check]], [[research-experiment-manager]]
