# External Generalization Bundle v10

This release updates the external-generalization/source-routing reproducibility bundle for VeriSec Forge.

## Contents

- Bundle: `verisec_forge_external_generalization_bundle_v10.zip`
- SHA256: `90dbaaf40665494b2b1fa62781c3e09d7ec59ed3cf3611e76b9b61a27ae3465c`
- Bytes: `29155005`
- Artifact count: `44`

## What Changed Since v9

- Adds `reports/assets/learned_content_router_stability.svg`.
- Updates `reproducibility/external_generalization_manifest.json` so the learned router stability figure is manifest-backed.
- Keeps the external-generalization/source-routing claim boundary unchanged: this is closed-world source-aware expert selection, not open-set source discovery.

## Rebuild Command

```powershell
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --include-generated `
  --output artifacts\verisec_forge_external_generalization_bundle_v10.zip
```

## Download Verification

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs
```
