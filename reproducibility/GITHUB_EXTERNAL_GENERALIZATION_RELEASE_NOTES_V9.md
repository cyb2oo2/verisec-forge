# External Generalization Bundle v9

This release adds cached char/token source-router stability artifacts alongside the existing diff-line stability report.

## Added

- cached `char_3_5` multi-seed pair-group subsampling stability report
- cached `token_1_2` multi-seed pair-group subsampling stability report
- reviewer-facing char/token/diff-line stability summary
- updated external-generalization manifest with three-view stability expected metrics

## Key Stability Results

- `char_3_5`, 50% train-pair fraction: routed BA mean `0.8649`
- `token_1_2`, 50% train-pair fraction: routed BA mean `0.8630`
- `diff_line_markers`, 50% train-pair fraction: routed BA mean `0.8634`
- Single matched-mixed BA: `0.8591`
- Oracle source-routed BA: `0.8664`

## Boundary

The new stability checks weaken the concern that the source-router result depends on a single brittle feature representation. The claim remains intentionally narrow: this is closed-world source-aware expert selection, not open-set source discovery, and not a uniform per-source gain.

## Bundle

- File: `verisec_forge_external_generalization_bundle_v9.zip`
- SHA256: `2a2ef2dd534404682837b9bf43d7ee6515b4609c7725bb2acd3a775a8df2adec`
- Bytes: `29153780`
- Artifact count: `43`
