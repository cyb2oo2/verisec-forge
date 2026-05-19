# PatchEval Cross-Source Specialization

This report evaluates whether the PatchEval-specific adapter behaves like a general paired-diff detector or a source-specialized expert.

## Results

| Dataset | PatchEval Adapter BA | Source Expert BA | Gap vs Expert | Group All-Correct | Orientation | Best Scalar BA |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `PrimeVul-time` | `0.8521` | `0.8835` | `-0.0314` | `0.795` | `0.8712` | `0.8169` |
| `DeltaSecommits` | `0.844` | `0.8563` | `-0.0123` | `0.8349` | `0.8379` | `0.8211` |
| `PatchEval` | `0.829` | `0.8086` | `0.0204` | `0.8141` | `0.8364` | `n/a` |

## Cross-Source Summary

- Mean cross-source PatchEval-adapter pair-coupled BA: `0.848`
- Mean gap to source expert: `-0.0218`
- PrimeVul scalar threshold best BA: `0.8169` at threshold `0.6`; pair-coupled BA: `0.8521`
- Delta scalar threshold best BA: `0.8211` at threshold `0.8`; pair-coupled BA: `0.844`

## Interpretation

The PatchEval adapter transfers non-trivially to PrimeVul-time and DeltaSecommits, but it remains below the matched source experts. This supports source-aware routing: PatchEval adaptation is useful in-domain, while cross-source deployment should prefer the dataset/source expert when available.
