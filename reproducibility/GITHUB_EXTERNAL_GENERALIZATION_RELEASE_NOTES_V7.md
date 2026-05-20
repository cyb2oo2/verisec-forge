# VeriSec Forge External Generalization Bundle v7

This release adds the learned router claim-boundary summary and SVG figure.

New in v7:

- reviewer-facing learned router claim-boundary report
- generated JSON summary consolidating statistical support, feature ablation, and leave-one-source stress
- SVG figure for routed-system balanced accuracy across feature views

Key claim boundary:

- Closed-world learned routing has BA delta `+0.0073` over the single matched-mixed checkpoint with 95% CI `[0.0000, 0.0145]`.
- Group all-correct remains non-significant with CI `[-0.0015, 0.0147]`.
- Feature ablation keeps the signal from being only a char n-gram story: token and diff-line routed BA are `0.8627` and `0.8649`.
- Leave-one-source stress keeps the claim closed-world: held-out routed-minus-oracle BA ranges from `-0.0250` to `-0.0077`.

Bundle:

- `verisec_forge_external_generalization_bundle_v7.zip`
- SHA256: `fc34a8f5d94a602289bf481dfaf053fcd0cef4730190cda8cc63542a9ce01a25`
- bytes: `29141784`
- artifact count: `39`
- manifest: `reproducibility/external_generalization_manifest.json`

Restore and verify:

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py `
  --bundle-name external_generalization_and_source_routing_inputs `
  --output artifacts\download_test_external_generalization_bundle_v7.zip

.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\external_generalization_manifest.json `
  --check-only `
  --include-generated
```

Scope boundary:

- This bundle supports the manifest-backed external-generalization, source-routing, learned-router, learned routed-system statistics, leave-one-source stress, feature-ablation, and claim-boundary summary chain.
- It does not include raw upstream datasets or model checkpoints.
- The claim-boundary summary is intentionally conservative and should be used as the reviewer-facing router statement.
