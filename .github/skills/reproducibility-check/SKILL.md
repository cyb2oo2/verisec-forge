---
name: reproducibility-check
description: >-
  Verify that an experiment, artifact, or claim can be reproduced from a clean
  state: hashed manifests, pinned deps, fixed seeds, and green anchor tests. Use
  before releasing a result, when a number can't be reproduced, or when auditing
  an artifact. Triggers: reproduce, reproducibility, manifest, SHA256, check-only,
  determinism, seed, pinned, fresh clone, audit, "can't reproduce".
---

# Reproducibility Check

Confirm that any promoted result in VeriSec Forge survives a from-scratch redo.
The repo's release chain is built on **SHA256 manifests + focused anchor tests +
a documented fresh-clone smoke path**; this skill runs and extends that chain.

## When to Use

- Before promoting a run into `reports/` or `paper/`.
- When a checked-in number cannot be reproduced.
- Auditing an artifact, bundle, or manifest for integrity.
- Preparing a release (`docs/RELEASE_CHECKLIST.md`).

## Instructions

### 1. Reproduce the environment
- Fresh venv, pinned install: `pip install -e ".[dev]"` (add `.[train]`/`.[serve]`
  only if the target needs them). Record Python (3.11) + resolved versions.

### 2. Run the fresh-clone smoke path
- The canonical minimal check (from README / `ci.yml`):
```powershell
python -m pytest -q `
  tests\test_veripatch_external_adapter.py `
  tests\test_ci_smoke_contract.py `
  tests\test_paper_artifacts.py `
  tests\test_report_index.py `
  tests\test_reproducibility_bundle.py
```

### 3. Validate manifests (`--check-only`)
- Every releasable artifact has a SHA256 manifest under `reproducibility/`.
  Validate without regenerating:
```powershell
python scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\veripatch_external_smoke_manifest.json --check-only
python scripts\reproduce_primevul_calibrated_router.py --check-only
python scripts\reproduce_primevul_evidence_coupled.py --check-only
```
- A hash mismatch is a **stop-the-line** event: find what changed before touching
  the manifest. Never "fix" a mismatch by regenerating the hash without
  understanding why the bytes changed.

### 4. Check determinism
- Same seed + same inputs → same output bytes (within documented tolerance). If
  not, isolate the nondeterminism (unset seed, unordered dict/set, GPU nondeterm,
  timestamp in artifact) and fix the source, not the manifest.

### 5. Verify claim traceability
- The number appears in a `reports/*.md` file, in `experiments/registry.json`,
  and (if paper-facing) in `paper/result_anchor_map.md`, all pointing at the same
  source. Run `tests/test_paper_artifacts.py` / `test_report_index.py`.

### 6. Record the reproduction level
- Tag the result: `report-backed`, `manifest-backed`, `ci-smoke`, or
  `protocol-backed`. Do not overstate (a protocol-backed plan is not a
  manifest-backed artifact).

## Best Practices & Guardrails

- **Do** treat a hash mismatch as evidence, not an inconvenience.
- **Do** fix nondeterminism at the source (seed/order), never by re-hashing.
- **Do** preserve path-escape and integrity checks in `vrf.reproducibility`.
- **Don't** downgrade the CI boundary to "reproduce" a GPU result in CI.
- **Don't** mark a smoke/pilot as `manifest-backed` model quality.

## Examples

**Restore a bundle and re-check**
```powershell
python scripts\download_reproducibility_bundle.py --bundle-name readout_confirmatory_inputs --restore
python scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\readout_confirmatory_manifest.json --check-only --include-generated
```

## Dependencies / Tools

- `scripts/build_reproducibility_bundle.py`, `scripts/reproduce_*`, `scripts/download_reproducibility_bundle.py`
- `reproducibility/` manifests; `vrf.reproducibility` (integrity/path-escape checks)
- `tests/test_reproducibility_bundle.py`, `test_ci_smoke_contract.py`, `test_paper_artifacts.py`
- `docs/CI_TESTING_STRATEGY.md`, `docs/RELEASE_CHECKLIST.md`, `REPRODUCIBILITY.md`
- Related skills: [[research-experiment-manager]], [[data-processing-pipeline]], [[github-workflow-automation]]
