# VeriSec Forge External Generalization Bundle v3

This release completes the learned content-routed system matrix for the observed three-source routes.

New in v3:

- DeltaSecommits expert cross-source predictions on PrimeVul-time
- DeltaSecommits expert cross-source predictions on PatchEval
- PrimeVul-time expert cross-source predictions on PatchEval
- default-threshold metric reports for the new cross-source eval runs
- learned content-routed system now uses a complete cross-prediction matrix for all observed learned routes, with `0` matched-mixed fallback rows

Bundle:

- `verisec_forge_external_generalization_bundle_v3.zip`
- SHA256: `a60358803f007dcf4c99610c81d56cfffda57910f0d2fac856332b064798a846`
- bytes: `29133720`
- artifact count: `34`
- manifest: `reproducibility/external_generalization_manifest.json`

Restore and verify:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs `
  --restore

.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only `
  --include-generated
```

Scope boundary: this bundle supports audit of the manifest-backed external-generalization/source-routing reports. It does not include model checkpoints or every historical exploratory run.
