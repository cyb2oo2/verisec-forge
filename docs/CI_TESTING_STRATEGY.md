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
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .[dev]
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_veripatch_external_adapter.py `
  tests\test_ci_smoke_contract.py `
  tests\test_paper_artifacts.py `
  tests\test_report_index.py `
  tests\test_reproducibility_bundle.py
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\veripatch_external_smoke_manifest.json `
  --check-only
```

The full local regression suite remains:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
