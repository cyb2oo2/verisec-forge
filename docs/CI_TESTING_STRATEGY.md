# CI Testing Strategy

This repository uses CI as an external-reproducibility smoke gate, not as a
new experimental result.

## What CI Covers

- VeriPatch-RR external adapter schema validation, template generation, and
  relational metric execution on the checked-in 30-pair smoke artifact.
- Paper scaffold integrity: the draft result anchors must match
  `paper/result_anchor_map.md`, and mapped anchors must point to retained
  reports or docs.
- Reproducibility helper behavior on synthetic manifests and a retained
  manifest `--check-only` pass for the checked-in external adapter smoke
  artifacts.
- Results-index rendering and required artifact-path checks.
- Windows and Linux path handling for the focused fresh-clone smoke path.

## What CI Does Not Cover

- CI does not train models, run GPU inference, or materialize tokenizer-specific
  runtime accounting for new models.
- CI does not convert the external smoke artifact into a benchmark result.
  The checked-in smoke artifact remains a 30-pair / 90-row adapter sanity
  check.
- CI does not establish tokenizer-neutral runtime visibility for other models.
  Full VeriPatch-RR claims still require model-specific runtime materialization
  and retained report artifacts.
- CI does not promote smoke, stress, pilot, or AI-filled audit evidence into
  broader model-quality claims.
- CI does not validate gitignored or release-bundle-only artifacts such as the
  PrimeVul calibrated-router manifest. Those manifests remain local/release
  reproducibility checks after their required artifacts are materialized.

## Local Equivalent

Run the same focused smoke path from a fresh clone:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements\py311-dev.lock
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_veripatch_external_adapter.py `
  tests\test_ci_smoke_contract.py `
  tests\test_paper_artifacts.py `
  tests\test_report_index.py `
  tests\test_reproducibility_bundle.py
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\veripatch_external_smoke_manifest.json `
  --check-only
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\current_training_synthesis_manifest.json `
  --include-generated `
  --check-only
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\repair_criteria_reports_manifest.json `
  --include-generated `
  --check-only
```

The full local regression suite remains:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The full suite assumes the local research environment has optional dependencies
for training, dataset-building, and demo tests. The fresh-clone contract is the
focused smoke path above.

## Dependency lock

`requirements/py311-dev.lock` pins the complete runtime plus test dependency
graph used by the Python 3.11 CI smoke. It intentionally excludes the optional
`train` and `serve` extras because CI does not run GPU training or vLLM. Refresh
it only after reviewing resolver changes:

```powershell
uv pip compile pyproject.toml --python-version 3.11 --extra dev `
  --output-file requirements\py311-dev.lock
```

The editable install uses `--no-deps` so `pyproject.toml` cannot silently
override the reviewed lock during CI.
