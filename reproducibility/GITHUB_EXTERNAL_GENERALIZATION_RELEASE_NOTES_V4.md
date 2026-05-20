# VeriSec Forge External Generalization Bundle v4

This release adds statistical credibility artifacts for the learned content-routed system.

New in v4:

- learned content-routed system bootstrap / paired-test statistics report
- pair-group bootstrap CIs for the single matched-mixed, oracle source-routed, and learned full-matrix routed systems
- learned-minus-single balanced-accuracy delta `+0.0073` with 95% CI `[0.0000, 0.0145]` and McNemar `p=0.024461`
- learned-minus-single group all-correct CI crosses zero, so the group-consistency gain is treated as non-significant

Bundle:

- `verisec_forge_external_generalization_bundle_v4.zip`
- SHA256: `4f47a47f14d1b95d5d425a514d58935401a3f3863da8f662167f6484539f6b4b`
- bytes: `29134862`
- artifact count: `35`
- manifest: `reproducibility/external_generalization_manifest.json`

Restore and verify:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs `
  --output artifacts\download_test_external_generalization_bundle_v4.zip

.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only `
  --include-generated
```

Scope boundary:

- This bundle supports the manifest-backed external-generalization, source-routing, learned-router, and learned routed-system statistics chain.
- It does not include raw upstream datasets or model checkpoints.
- The learned router result should be read as source/expert routing from code-diff content, not as standalone vulnerability semantic understanding.
