# Reproducing the current review

The evidence inventory preserves the original local byte hashes. Where Git's LF representation differs from the recorded Windows CRLF bytes, `git_blob_sha256` additionally binds the committed representation. Only line-ending-equivalent files receive this second hash; the hygiene check accepts either recorded representation, not arbitrary normalization. This keeps the original evidence and prior Git blobs unchanged across platforms.

The authoritative interpretation is the [scientific review](reports/scientific_review_2026_09_07/REVIEW.md). Historical reports were retired; their JSON/CSV evidence remains at its original path so analysis scripts and source hashes stay usable.

For a fresh clone:

```powershell
python scripts/build_reproducibility_bundle.py --manifest reproducibility/veripatch_external_smoke_manifest.json --check-only
```

For the local research workspace:

```powershell
python reports/scientific_review_2026_09_07/audit_existing_artifacts.py
```

This writes `audit_recheck.json` beside the script, preserving the original `audit_results.json` snapshot. It requires local ignored inputs and predictions, runs no model, and does not download missing artifacts. A completed recheck can contain failed findings; inspect `manifest_check` and `raw_repair_gate`.

The original review checked 45 manifest entries: 44 passed and one mismatched. Cleanup removes retired Markdown outputs from active generated-artifact lists and records their original entries in the cleanup manifest. Expected hashes for retained evidence are unchanged. Subsequent counts differ from the original snapshot.

**Diagnosed mismatch:** the frozen-readout train-cache differs only in line endings. Original bytes recovered from the local historical ZIP match the expected hash. Existing evidence and original expected hashes remain unchanged. The derived manifest validates 43 entries.

Run P0 reanalysis using the repository research environment (requires locally retained source data, predictions, ZIP and tokenizer; no model weights are loaded):

```powershell
.venv/Scripts/python.exe scripts/reanalyze_measurement_p0.py
.venv/Scripts/python.exe scripts/build_reproducibility_bundle.py --manifest reports/scientific_review_2026_09_07/p0/recovered_inputs_manifest.json --check-only
```

Results are written to `reports/scientific_review_2026_09_07/p0/results.json`; corrected runtime metadata goes to ignored `data/processed/p0_measurement_v2/`. These are exploratory reanalyses with explicit tie abstention and stratified null definitions, not replacements for the original audit snapshot.

Existing release metadata describes historical published bundles, not a certification of the cleaned checkout or scientific validity. Local checks do not establish fresh training reproducibility. See [evidence policy](docs/EVIDENCE_HIERARCHY.md).
