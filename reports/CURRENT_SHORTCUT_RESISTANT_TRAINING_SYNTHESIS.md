# Current Controlled Training Synthesis

> **Status: report-backed, bounded evidence.** This synthesis is rebuilt from
> retained evaluator JSONs. It does not rerun training or promote a model.

## Matched-compute backbone control

| Backbone / precision | Seed 7 discordant | Seed 123 discordant | Mean | Seed SD |
| --- | ---: | ---: | ---: | ---: |
| Qwen2.5-Coder-1.5B bf16 | `0.4389` | `0.3611` | `0.4000` | `0.0550` |
| Qwen2.5-Coder-7B nf4 | `0.5167` | `0.5167` | `0.5167` | `0.0000` |
| Qwen2.5-Coder-3B bf16 | `0.6333` | `0.5667` | `0.6000` | `0.0471` |

At matched data and optimizer steps, the observed two-seed system ordering is 1.5B bf16 < 7B nf4 < 3B bf16 on discordant pairs.

**Boundary.** This is a two-seed, one-model-family system comparison. The 7B quantization regime is a precision confound. The closest same-seed 7B-to-3B gap (0.0500) is below the largest within-arm seed range (0.0778). The zero observed 7B seed SD is not evidence of zero training variance.

## Decontamination and discordant-supply control

| Training set | Mean discordant | Mean balanced delta | Discordant seed range |
| --- | ---: | ---: | ---: |
| v1 balanced (2,208 pairs) | `0.6000` | `0.2166` | `0.0666` |
| v2 decontaminated (2,164 pairs) | `0.6111` | `0.2175` | `0.0334` |
| v3 mined (3,160 pairs) | `0.6195` | `0.2167` | `0.0167` |

Decontamination and mined discordant supply leave mean balanced delta nearly unchanged and move mean discordant accuracy only slightly across the three two-seed arms.

**Boundary.** The largest between-arm mean gap (0.0195) is below the largest within-arm seed range (0.0666) but slightly above the smallest (0.0167); this two-seed control does not establish a data-supply improvement.

## Seed precision analysis

Using the larger observed bf16 seed SD (`0.0550`), a three-seed Student-t interval would still have a projected 95% half-width of `0.1367`. A sensitivity calculation requires **8 seeds** for half-width at most `0.05`, or **22 seeds** for half-width at most `0.025`.

A third seed is a useful minimum diagnostic for direction and seed collisions, but is not sufficient for a sharp mean estimate. Pair-level binomial intervals are not substituted for seed uncertainty.

**Caution.** Variance planning from two seeds is unstable; these counts are sensitivity calculations, not a preregistered power guarantee.

## Claim boundary

The controlled training results are bounded experimental evidence for experimental design and shortcut diagnosis, but not evidence of a general secure-patch reasoning solution.

Machine-readable source: `reports/current_shortcut_resistant_training_synthesis_v1.json`.
