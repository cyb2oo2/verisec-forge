# Polarity-Balanced Training (sampling-level lever)

Config: `configs/research_polarity_balanced_v1.json`
Checkpoint: `checkpoints/cls_secure_code_polarity_balanced_qwen15b_lora_v1`
Data: `data/processed/secure_code_polarity_balanced_train_v1.jsonl`
Artifacts: `reports/veripatch_rr_polarity_balanced_slice.json`,
`reports/veripatch_rr_polarity_balanced_replication.json`,
`reports/secure_code_polarity_balanced_train_v1_summary.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All previous artifacts
unchanged. Ablation reference: the prose-native pilot, same rendering, same
backbone, compute-matched.

## Verdict

**The most promising result in this line of work — and the first where the rise
in anti-polarity accuracy is not paid for by a collapse elsewhere.**

| Success criterion | Result |
| --- | --- |
| 1. Accuracy when polarity is wrong ≫ 0.25–0.30 | **partially met**: `0.1944 → 0.2778` on prose; enters the target band but remains far below the `0.5` chance line |
| 2. Not paid for by collapse in concordant accuracy | **met**: concordant falls only `0.9481 → 0.8933` |
| 3. Matches/exceeds prose control on balanced eval slice | **met**: `+0.0812`, CI `[+0.0357, +0.1266]`, `p=0.001` |

## Training set

Built from the *training* sources with the v4 cleaning pipeline. (The v4 suite
itself is the evaluation pool, so it cannot supply training pairs; "start from
the clean v4 suite" is implemented as "apply the same invariants".)

| Cell | before balancing | after |
| --- | ---: | ---: |
| gold=A, net=+ | 1,661 | **254** |
| gold=A, net=− | 277 | **254** |
| gold=B, net=+ | 254 | **254** |
| gold=B, net=− | 1,616 | **254** |

| Item | Value |
| --- | --- |
| Sources | PrimeVul time-disjoint train, PatchEval train, DeltaSecommits train (v2, newline-fixed) |
| Source pairs | 5,854 |
| Excluded — held out | 368 (2,101 keys: v4 suite + all four eval pools) |
| Excluded — incomplete / non-mirror / flat / zero-net | 1,266 / 301 / 1 / 110 |
| **Training pairs / rows** | **1,016 / 2,032** (26% retention) |
| Rendering | `split_view` prose only |
| Init | prose-native pilot |
| Schedule | 2 epochs — compute-matched to the pilot's 1 epoch on 1,736 pairs |
| Train loss | `0.65` (pilot reached `0.46`) |

The loss plateau near `ln 2 = 0.693` is itself the intended signal: with the four
cells equalised, the polarity shortcut carries no gradient, so the easy route to
low loss is gone.

## Decisive metric

Population estimator over 1,202 pairs:

| System | rendering | concordant | **discordant** | balanced Δ |
| --- | --- | ---: | ---: | ---: |
| prose-native pilot | glyph | `0.9413` | `0.1778` | `+0.0595` |
| **balanced-trained** | glyph | `0.9354` | `0.1889` | `+0.0622` |
| prose-native pilot | prose | `0.9481` | `0.1944` | `+0.0713` |
| **balanced-trained** | **prose** | `0.8933` | **`0.2778`** | **`+0.0856`** |

On prose, discordant accuracy rises `+0.0834` while concordant falls `-0.0548`.

**This is not dilution.** INLP established the test: a decision drifting toward
random raises discordant accuracy while holding the *balanced* delta constant.
Here the balanced delta **rises**, `+0.0713 → +0.0856`. The gain is larger than
the loss, so something beyond re-randomisation happened.

The effect is confined to the prose rendering, which is the only one trained on —
glyph discordant moves `0.1778 → 0.1889`, i.e. not at all.

## Balanced evaluation slice (308 pairs)

| Family | System | canonical | equivariance | both-correct | Δ vs control | 95% CI |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| prose | control | `0.5000` | `0.9903` | `0.4968` | — | — |
| prose | prose-native pilot | `0.5649` | exact | `0.5649` | `+0.068` | `[+0.0292, +0.1071]` |
| prose | **balanced-trained** | `0.5779` | exact | **`0.5779`** | **`+0.0812`** | `[+0.0357, +0.1266]` |
| glyph | control | `0.5000` | `1.0000` | `0.5000` | — | — |
| glyph | balanced-trained | `0.5455` | exact | `0.5455` | `+0.0455` | `[+0.0032, +0.0877]` |

Best balanced-slice result recorded in this repository.

## Full clean set (1,245 pairs) — the cost

| Family | System | canonical | both-correct | Δ vs control | 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| prose | control | `0.8321` | `0.8273` | — | — |
| prose | prose-native pilot | `0.8201` | `0.8201` | `-0.0072` | `[-0.0233, +0.0088]` |
| prose | balanced-trained | `0.7871` | `0.7871` | `-0.0402` | `[-0.0610, -0.0193]` |
| glyph | balanced-trained | `0.8129` | `0.8129` | `-0.0153` | `[-0.0329, +0.0024]` |

Training only on the balanced distribution costs full-set accuracy: prose falls
from statistical parity with the control (`-0.0072`) to a significant deficit
(`-0.0402`). That is the expected trade — the model no longer exploits a
regularity that holds in 85% of the full population.

## Limitation: independent inference degenerates

| System | rendering | independent canonical | independent equivariance | independent both-correct |
| --- | --- | ---: | ---: | ---: |
| balanced-trained | prose | `0.5000` | `0.0325` | `0.0162` |
| balanced-trained | glyph | `0.7028` | `0.5205` | `0.4659` |

Per-rendering decisions on prose are effectively frozen (equivariance `0.0325`:
the same answer on canonical and swap for ~97% of pairs). Every gain reported
above flows through the antisymmetric projection. The balanced objective has
sharpened the *pairwise* score without producing a usable standalone classifier.

## Reading

Three representation-level interventions failed; the sampling-level lever is the
first to move the decisive metric without a compensating collapse:

| Intervention | discordant (prose) | concordant (prose) | balanced Δ |
| --- | ---: | ---: | ---: |
| prose-native pilot | `0.1944` | `0.9481` | `+0.0713` |
| gradient-reversal λ=1.0 | `0.1944` | `0.9335` | `+0.0640` |
| INLP round 12 (frozen head) | `0.5056` | `0.6037` | `+0.0546` |
| **polarity-balanced training** | **`0.2778`** | `0.8933` | **`+0.0856`** |

INLP reached a higher discordant number by destroying the decision. Balanced
training reaches a lower one while keeping concordant accuracy at `0.89`, and is
the only row where the balanced delta improves.

The honest size of the result: `0.2778` against a `0.5` chance line means the
model is still wrong on 72% of the pairs where polarity misleads. This is
progress on a metric that had not moved across three prior interventions, not a
demonstration of relational understanding.

## Recommended next step

Two cheap follow-ups, in order:

1. **Scale the balanced set.** 1,016 pairs is small and the cells are capped by
   254 discordant examples per side. Mining more discordant pairs — from
   additional sources, or by relaxing the sampling to weight rather than
   truncate — directly raises the ceiling. The effect appeared at 1,016 pairs;
   the question is whether it grows.
2. **Train on balanced *glyph* as well as prose.** The gain is currently
   rendering-local. A mixed balanced set would show whether the effect is a
   property of the objective or of the prose encoding.

Combining balanced sampling with the adversarial term is **not** indicated yet:
the adversary was shown ineffective in isolation, and mixing the two would make
attribution impossible.

## Follow-up: replicated, but does not scale

See [POLARITY_BALANCED_REPLICATION_AND_SCALING.md](POLARITY_BALANCED_REPLICATION_AND_SCALING.md).

* **Seed 123 replicates**: prose discordant `0.2722` (vs `0.2778` here), balanced
  Δ `+0.0887` (vs `+0.0856`). The effect is stable.
* **Scaling to 552 pairs/cell does not help**: prose discordant `0.2611`,
  balanced Δ `+0.0743`. Doubling the discordant examples at matched compute did
  not continue the rise.

Three runs place prose discordant accuracy in a `0.2611–0.2778` band. Balanced
sampling reliably moves the metric from `~0.19` to `~0.27` and then stops.

## Claim boundary

One run, one seed, 1,016 balanced training pairs (254 per cell), prose-only
rendering, one backbone, length 1024, 2 epochs, initialised from the prose-native
pilot. Evaluated on 1,245 held-out pairs across four sources with zero training
overlap. Balanced-slice results rest on 308 pairs. The replication and scaling
follow-ups above supersede this report's single-seed caveat.
