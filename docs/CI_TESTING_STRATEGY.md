# CI Testing Strategy

CI validates current navigation, evidence inventory, adapter and manifest tooling. It does not train models and does not convert the external smoke artifact into a benchmark result.

```powershell
python -m pytest -q tests/test_repository_hygiene.py tests/test_veripatch_external_adapter.py tests/test_ci_smoke_contract.py tests/test_report_index.py tests/test_reproducibility_bundle.py
python scripts/build_reproducibility_bundle.py --manifest reproducibility/veripatch_external_smoke_manifest.json --check-only
```

Full regression uses `python -m pytest -q` after installing `.[dev,source-audit]`. A PrimeVul calibrated-router manifest check requires local/release inputs and is outside portable CI. CI also runs the offline constant-A adapter demonstration; it needs no model or API.

Tests enforcing removed paper prose were retired. Computational tests remain. Historical artifact checks do not endorse old visibility or repair claims. Software checks passing do not resolve the scientific review findings.
