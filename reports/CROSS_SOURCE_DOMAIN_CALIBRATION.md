# Cross-Source Domain Calibration

This report evaluates whether the matched mixed-source checkpoint should use one global threshold or source-aware thresholds across PrimeVul-time and DeltaSecommits.

## Summary

- Best shared threshold: `0.3` with global BA `0.8714` and F1 `0.8724`.
- Source-aware thresholds: PrimeVul-time `0.4`, DeltaSecommits `0.3`.
- Source-aware global BA/F1: `0.8714` / `0.8707`.
- Source-aware minus best shared BA/F1: `0.0` / `-0.0017`.

## Shared Threshold Sweep

| Threshold | Global BA | PrimeVul BA | Delta BA | Global F1 |
| ---: | ---: | ---: | ---: | ---: |
| `0.1` | `0.8574` | `0.8624` | `0.8456` | `0.8641` |
| `0.2` | `0.8664` | `0.87` | `0.8578` | `0.8693` |
| `0.3` | `0.8714` | `0.8732` | `0.867` | `0.8724` |
| `0.4` | `0.8682` | `0.8732` | `0.8563` | `0.8667` |
| `0.5` | `0.8628` | `0.8694` | `0.8471` | `0.8585` |
| `0.6` | `0.8606` | `0.8681` | `0.8425` | `0.8542` |
| `0.7` | `0.8574` | `0.8662` | `0.8364` | `0.8485` |
| `0.8` | `0.8533` | `0.8604` | `0.8364` | `0.8415` |
| `0.9` | `0.8412` | `0.8476` | `0.8257` | `0.8236` |

## Pair-Coupled Snapshot

| Source | Pair-Coupled BA | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: |
| `PrimeVul-time` | `0.8809` | `0.8673` | `0.883` |
| `DeltaSecommits` | `0.8486` | `0.844` | `0.8471` |

## Interpretation

The matched mixed-source checkpoint has different best thresholds on PrimeVul-time and DeltaSecommits. However, source-aware thresholding does not materially improve over the best shared threshold on the combined eval; the remaining cross-source gap is in pair-coupled consistency, not just scalar threshold calibration.
