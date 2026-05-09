# Reproducibility Artifact Release Checklist

Use this checklist when publishing `artifacts/verisec_forge_primevul_repro_bundle.zip` to GitHub Releases, Hugging Face Datasets, or another stable artifact host.

## Current Local Bundle

- Filename: `verisec_forge_primevul_repro_bundle.zip`
- Byte size: `5731758`
- SHA256: `e4713b7014ca9bae3404e8f24d1ab37eeda0147f4860b78d48042f7d91c03273`
- Unique artifact count: `6`
- Duplicate manifest path intentionally deduplicated: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`

## Pre-Upload

1. Rebuild the bundle from current local artifacts:

```powershell
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\primevul_calibrated_router_manifest.json `
  --manifest reproducibility\primevul_evidence_coupled_manifest.json `
  --output artifacts\verisec_forge_primevul_repro_bundle.zip
```

2. Confirm the printed SHA256 and byte size match `reproducibility/release_artifacts.json`.
3. Do not commit the zip file; `artifacts/` is intentionally gitignored.

## Upload

1. Upload `artifacts/verisec_forge_primevul_repro_bundle.zip` to the chosen stable host.
2. Copy the final public URL into `reproducibility/release_artifacts.json`.
3. Keep `sha256` and `bytes` unchanged unless the bundle is rebuilt.

## Post-Upload Smoke Test

After filling the public URL, run:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py
```

For a clean restore test:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py --restore
.\.venv\Scripts\python.exe scripts\reproduce_primevul_calibrated_router.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
```

## Claim Boundary

Before the URL is filled, the project should be described as local bundle-ready. After the URL is filled and smoke-tested, it can be described as public bundle-assisted reproducible for the manifest-backed PrimeVul router and evidence-coupled chains.
