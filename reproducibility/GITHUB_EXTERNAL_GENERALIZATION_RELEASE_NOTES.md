# VeriSec Forge External Generalization Bundle v1

This release contains the manifest-backed local artifacts for the external-generalization and source-routing chain:

- PrimeVul time-disjoint paired-diff metadata and predictions
- DeltaSecommits paired-diff metadata and predictions
- PatchEval paired-diff metadata and multi-seed predictions
- PatchEval reverse cross-source prediction artifacts
- generated reports for three-source adapter mixture and source-router analyses

Bundle:

- `verisec_forge_external_generalization_bundle.zip`
- SHA256: `7e2484bdc8ac5d1b1e3295e5563df36b1b08f6a41e048f886f668bf5b783407f`
- bytes: `29046027`
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
