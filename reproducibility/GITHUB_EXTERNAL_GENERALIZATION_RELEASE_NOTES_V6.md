# VeriSec Forge External Generalization Bundle v6

This release adds learned content-router feature ablation artifacts.

New in v6:

- feature ablation report for diff-body-only learned source/expert routing
- end-to-end routed-system evaluation for character n-gram, token n-gram, and diff-line marker routers
- explicit robustness boundary for the claim that routing is not only a single character-fingerprint artifact

Key feature-ablation results:

- `char_3_5`: route row accuracy `0.9063`, routed-system BA `0.8664`
- `token_1_2`: route row accuracy `0.7106`, routed-system BA `0.8627`
- `diff_line_markers`: route row accuracy `0.7778`, routed-system BA `0.8649`
- single matched-mixed BA: `0.8591`
- oracle source-routed BA: `0.8664`

Bundle:

- `verisec_forge_external_generalization_bundle_v6.zip`
- SHA256: `01db24d1c217fe154903b02a6e2ea1d943bccb6569d5b02dd6221562e256bffa`
- bytes: `29139984`
- artifact count: `37`
- manifest: `reproducibility/external_generalization_manifest.json`

Restore and verify:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs `
  --output artifacts\download_test_external_generalization_bundle_v6.zip

.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only `
  --include-generated
```

Scope boundary:

- This bundle supports the manifest-backed external-generalization, source-routing, learned-router, learned routed-system statistics, leave-one-source stress, and feature-ablation chain.
- It does not include raw upstream datasets or model checkpoints.
- Feature ablation is a robustness check, not a new headline metric; group consistency remains a conservative claim boundary.
