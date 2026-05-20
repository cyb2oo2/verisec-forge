# VeriSec Forge External Generalization Bundle v5

This release adds the learned content-router leave-one-source stress report.

New in v5:

- leave-one-source-out open-set boundary report for learned diff-body source routing
- held-out source routing distributions and routed-system metrics against single matched-mixed and source-specific oracle systems
- explicit claim boundary: learned source routing is currently a closed-world source-aware expert selector, not an unseen-source expert discovery mechanism

Key stress results:

- Held-out PrimeVul-time routed existing experts trail source-specific oracle by `-0.0250` balanced accuracy.
- Held-out DeltaSecommits routed existing experts trail source-specific oracle by `-0.0077` balanced accuracy.
- Held-out PatchEval routed existing experts trail source-specific oracle by `-0.0242` balanced accuracy.
- No matched-mixed fallback rows are used in the stress report because the full observed cross-prediction matrix is materialized.

Bundle:

- `verisec_forge_external_generalization_bundle_v5.zip`
- SHA256: `029f06acf019c9e1da7a887dbeb5b5c19f2e11b0e40b437bfcf314659a5940ae`
- bytes: `29137509`
- artifact count: `36`
- manifest: `reproducibility/external_generalization_manifest.json`

Restore and verify:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs `
  --output artifacts\download_test_external_generalization_bundle_v5.zip

.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only `
  --include-generated
```

Scope boundary:

- This bundle supports the manifest-backed external-generalization, source-routing, learned-router, learned routed-system statistics, and leave-one-source stress chain.
- It does not include raw upstream datasets or model checkpoints.
- The leave-one-source result is intentionally conservative: it prevents overclaiming source routing as open-set generalization.
