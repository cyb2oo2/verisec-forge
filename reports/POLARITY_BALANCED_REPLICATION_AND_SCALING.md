# Polarity-Balanced Training: Seed Replication and Data Scaling

Reference run: `reports/POLARITY_BALANCED_TRAINING_V1.md` (254 pairs/cell, seed 7).
All previous artifacts unchanged.

| Experiment | Checkpoint | Artifacts |
| --- | --- | --- |
| Seed replication | `cls_secure_code_polarity_balanced_seed123_qwen15b_lora_v1` | `veripatch_rr_polarity_balanced_seed123_{replication,slice}.json` |
| Data scaling | `cls_secure_code_polarity_balanced_scaled_qwen15b_lora_v1` | `veripatch_rr_polarity_balanced_scaled_{replication,slice}.json` |

## Verdict

**1. The effect replicates cleanly across seeds.**
**2. It does not scale with data — 2.17× more discordant examples does not raise
discordant accuracy.** The `~0.27` level looks like a ceiling for this approach.

## Experiment 1 — seed replication

Identical settings, seed `7 → 123` for both cell sampling and training. The
balanced set was rebuilt from scratch with the new seed (254/cell again).

Population estimator over 1,202 pairs:

| Rendering | Run | concordant | **discordant** | balanced Δ | 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| prose | seed 7 | `0.8933` | **`0.2778`** | `+0.0856` | `[+0.0527, +0.1201]` |
| prose | **seed 123** | `0.9051` | **`0.2722`** | `+0.0887` | `[+0.0563, +0.1224]` |
| glyph | seed 7 | `0.9354` | `0.1889` | `+0.0622` | `[+0.0328, +0.0920]` |
| glyph | seed 123 | `0.9315` | `0.1944` | `+0.0630` | `[+0.0331, +0.0933]` |

Balanced evaluation slice (308 pairs), both-directions-correct:

| Rendering | control | seed 7 | seed 123 | seed-123 Δ vs control | 95% CI |
| --- | ---: | ---: | ---: | ---: | --- |
| prose | `0.4968` | `0.5779` | `0.5877` | `+0.0909` | `[+0.0455, +0.1364]` |
| glyph | `0.5000` | `0.5455` | `0.5519` | `+0.0519` | `[+0.0097, +0.0942]` |

Discordant accuracy moves by `-0.0056` and the balanced delta by `+0.0031`
between seeds. **The result is stable**, and the reference run should no longer be
treated as a single-seed observation.

## Experiment 2 — scaling the balanced set

Mined additional discordant pairs by widening the source pool: PrimeVul
time-disjoint train, PatchEval *all*, DeltaSecommits *all* (v2), and CrossVul
pairs outside the held-out evaluation keys.

| Cell | reference | scaled |
| --- | ---: | ---: |
| gold=A, net=+ | 254 | **552** |
| gold=A, net=− | 254 | **552** |
| gold=B, net=+ | 254 | **552** |
| gold=B, net=− | 254 | **552** |
| **Training pairs** | **1,016** | **2,208** |

Pre-balancing pool grew from `1,661 / 277 / 254 / 1,616` to
`3,169 / 581 / 552 / 3,258`. One epoch on 2,208 pairs is compute-matched to two
epochs on 1,016 (2,208 vs 2,032 updates), so this isolates data scale from
compute.

| Rendering | Run | concordant | **discordant** | balanced Δ | 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| prose | 254/cell | `0.8933` | **`0.2778`** | `+0.0856` | `[+0.0527, +0.1201]` |
| prose | **552/cell** | `0.8875` | **`0.2611`** | `+0.0743` | `[+0.0416, +0.1078]` |
| glyph | 254/cell | `0.9354` | `0.1889` | `+0.0622` | `[+0.0328, +0.0920]` |
| glyph | 552/cell | `0.9384` | `0.1944` | `+0.0664` | `[+0.0374, +0.0981]` |

Balanced slice, both-directions-correct:

| Rendering | control | 254/cell | 552/cell | 552/cell Δ vs control |
| --- | ---: | ---: | ---: | ---: |
| prose | `0.4968` | `0.5779` | `0.5552` | `+0.0584` `[+0.0097, +0.1071]` |
| glyph | `0.5000` | `0.5455` | `0.5552` | `+0.0552` `[+0.0130, +0.0974]` |

**Doubling the discordant examples did not raise discordant accuracy.** On prose
it fell slightly (`0.2778 → 0.2611`); on glyph it rose slightly
(`0.1889 → 0.1944`). Every interval overlaps its reference heavily. The success
signal specified for this experiment — discordant accuracy continuing to rise —
did not occur.

## Reading the two results together

Three independent runs now place prose discordant accuracy in a narrow band:

| Run | discordant (prose) | balanced Δ (prose) |
| --- | ---: | ---: |
| 254/cell, seed 7 | `0.2778` | `+0.0856` |
| 254/cell, seed 123 | `0.2722` | `+0.0887` |
| 552/cell, seed 7 | `0.2611` | `+0.0743` |

The spread is `0.017` across a seed change and a 2.17× data increase. That
consistency is what makes the negative scaling result informative rather than
noisy: balanced sampling reliably moves discordant accuracy from `~0.19` to
`~0.27`, and then stops. More balanced data does not continue the trend.

The natural interpretation is that balanced sampling removes the *gradient* from
the polarity shortcut but does not supply content-based features the model can
substitute. It relocates the model to a different point, not onto a better
trajectory. That is consistent with the probe result (polarity linearly decodable
at `0.90` from every checkpoint tested) and with INLP (polarity redundantly
encoded across many directions).

`0.27` against a `0.5` chance line means the model remains wrong on 73% of pairs
where polarity misleads.

## Caveats

**CrossVul is no longer zero-shot for the scaled checkpoint.** The scaled
training set draws on CrossVul pairs outside the 350 held-out evaluation keys, so
that checkpoint has seen the CrossVul distribution. Its CrossVul evaluation
numbers are not comparable to the external-transfer results in
`reports/VERIPATCH_RR_STRUCTURAL_CONTROL_CROSSVUL_V3.md`. The three other
sources remain clean, and the reference and seed-123 checkpoints are unaffected —
neither used CrossVul.

**Compute-matched, not epoch-matched.** The scaled run saw each example once; the
reference saw each twice. A 2-epoch scaled run (double compute) has not been
tried and would separate "more data does not help" from "each example needs more
than one pass".

**Full-set cost persists.** Prose full-set both-correct sits at `0.7944`
(seed 123) and `0.7807` (scaled) against the control's `0.8273` — the balanced
objective continues to trade full-population accuracy for balanced-slice
performance.

## Claim boundary

Two seeds at 254/cell, one seed at 552/cell; prose-only training rendering; one
backbone; length 1024; initialised from the prose-native pilot. Evaluated on
1,245 held-out pairs (1,202 with defined polarity) across four sources.
Balanced-slice figures rest on 308 pairs. The scaling conclusion covers one
doubling at fixed compute, not an extended scaling curve.
