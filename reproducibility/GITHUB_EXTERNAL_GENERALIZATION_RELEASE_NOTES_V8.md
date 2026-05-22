# External Generalization Bundle v8

This release adds the learned content-router stability report to the external-generalization/source-routing artifact bundle.

## Added

- multi-seed pair-group subsampling stability report for the weaker diff-line source router
- generated JSON artifact for the stability summary
- updated external-generalization manifest with stability expected metrics

## Key Stability Result

- Diff-line router at `0.5` train-pair fraction: routed BA mean `0.8634`, range `[0.8627, 0.8638]`
- Diff-line router at `1.0` train-pair fraction: routed BA `0.8642`
- Single matched-mixed BA: `0.8591`
- Oracle source-routed BA: `0.8664`

## Boundary

The stability result supports source-aware expert routing as a robust closed-world system layer, but it does not turn routing into open-set source discovery. Per-source tradeoffs remain uneven: PrimeVul-time is slightly below the single model, DeltaSecommits matches the source expert, and PatchEval gains most over the single model while remaining below oracle.

## Bundle

- File: `verisec_forge_external_generalization_bundle_v8.zip`
- SHA256: `f6df036e21f3cec4de777807289835390bcdf5f9e3ac6ed14a4c7edea2a577c9`
- Bytes: `29145699`
- Artifact count: `40`
