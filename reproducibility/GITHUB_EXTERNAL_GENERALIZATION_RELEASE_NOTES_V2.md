# VeriSec Forge External Generalization Bundle v2

This release updates the external-generalization/source-routing bundle with the learned content-routed system report and its additional prediction dependencies.

New in v2:

- learned diff-body routed-system report
- DeltaSecommits PrimeVul-checkpoint zero-shot prediction artifact
- PatchEval matched-mixed raw prediction artifact
- manifest coverage increases from `25` to `28` artifacts

Bundle:

- `verisec_forge_external_generalization_bundle_v2.zip`
- SHA256: `148d18cb80a85647e960b0d228cfcc13dd97326ae5a5eb23ebf6ea50aa432808`
- bytes: `29094120`
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
