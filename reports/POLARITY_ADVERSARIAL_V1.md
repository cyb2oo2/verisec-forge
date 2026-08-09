# Polarity-Adversarial Training (Option A: gradient reversal)

Trainer: `scripts/train_polarity_adversarial.py`
Configs: `configs/research_polarity_adversarial_v1.json` (λ=0.1),
`configs/research_polarity_adversarial_lambda1_v1.json` (λ=1.0)
Status artifacts: `reports/polarity_adversarial_train_status_v1.json`
Evaluation: `reports/veripatch_rr_adv_slice.json`,
`reports/veripatch_rr_adv_lambda01_replication.json`,
`reports/veripatch_rr_adv_lambda1_replication.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts
unchanged. Ablation baseline: the non-adversarial prose-native pilot
(`reports/PROSE_NATIVE_PILOT_V1.md`), same data, same schedule, same seed.

## Verdict

**Not promising. The adversarial term does not move the decisive metric at
either λ, and at λ=1.0 it reproduces the ablation baseline exactly.**

| Success criterion | Result |
| --- | --- |
| 1. Accuracy when polarity is wrong ≫ 0.25–0.30 | **failed** (`0.1944`, unchanged) |
| 2. Matches/exceeds prose control on balanced slice | met (`+0.064`, CI `[+0.035, +0.095]`) |
| 3. Advantage not confined to one rendering | met (glyph `+0.0566`, prose `+0.0640`) |

## Implementation

An auxiliary head (Linear 1536→128 → Tanh → Linear 128→1) predicts the sign of
the pair's net character change from the **same pooled terminal representation**
the relational head reads. A gradient reversal layer sits between them, so the
head learns polarity while the encoder is pushed to remove it.

```
total = L_main + aux_weight * L_polarity     (GRL scales encoder grads by -λ)
```

Polarity labels come from the pair's **glyph** rendering — the prose rendering
carries no `+`/`-` lines, so measuring polarity there would report zero for every
row. Rows with zero net change are masked from the auxiliary loss. Training data
is prose-only (`prose_fraction = 1.0`), 1,736 pairs, identical to the ablation.

## The adversary never wins

Auxiliary polarity accuracy, by epoch fraction — this is the diagnostic that says
whether polarity is actually being removed. It should fall toward `0.5`.

| epoch | λ=0.1 main | λ=0.1 **aux acc** | λ=1.0 main | λ=1.0 **aux acc** |
| ---: | ---: | ---: | ---: | ---: |
| 0.09 | `0.6468` | `0.5323` | `0.6484` | `0.5323` |
| 0.37 | `0.3954` | `0.5994` | `0.3921` | `0.5801` |
| 0.55 | `0.4113` | `0.7179` | `0.4102` | `0.6442` |
| 0.74 | `0.3076` | `0.6941` | `0.3484` | `0.6020` |
| 1.00 | `0.6402` | **`0.6828`** | `0.6036` | **`0.5858`** |

At λ=0.1 the auxiliary accuracy *rises* to `0.68` — the encoder retains polarity
and the reversal is simply too weak. At λ=1.0 it peaks at `0.646` and settles at
`0.586`, so the tenfold increase does suppress polarity readability, but **never
to chance**. The main task converges at both settings, so λ could be raised
further.

## The decisive metric does not move

Accuracy conditional on the polarity rule being wrong, population estimator over
1,202 pairs:

| System | glyph | prose |
| --- | ---: | ---: |
| glyph-trained baseline | `0.1833` | — |
| prose-native pilot (ablation, no adversary) | `0.1778` | `0.1944` |
| **polarity-adversarial λ=0.1** | `0.1889` | `0.2000` |
| **polarity-adversarial λ=1.0** | `0.1778` | `0.1944` |

λ=1.0 reproduces the ablation baseline to four decimals on both renderings.
λ=0.1 differs by `+0.006`. Against a target of ≫0.25–0.30 and a chance line of
`0.50`, neither is movement.

## Aggregate metrics (unchanged, as expected)

Balanced slice, 308 pairs, both-directions-correct:

| Family | control | λ=0.1 | λ=1.0 | ablation |
| --- | ---: | ---: | ---: | ---: |
| glyph | `0.5000` | `0.5487` | `0.5519` | `0.5487` |
| prose | `0.4968` | `0.5649` | `0.5552` | `0.5649` |

Full clean set, 1,245 pairs, both-directions-correct:

| Family | control | λ=0.1 | λ=1.0 | ablation |
| --- | ---: | ---: | ---: | ---: |
| glyph | `0.8281` | `0.8104` | `0.8112` | `0.8169` |
| prose | `0.8273` | `0.8201` | `0.8096` | `0.8201` |

Population balanced deltas with disjoint-half replication:

| System | glyph delta | 95% CI | halves | prose delta | 95% CI | halves |
| --- | ---: | --- | --- | ---: | --- | --- |
| λ=0.1 | `+0.0612` | `[+0.0314, +0.0916]` | `+0.0706` / `+0.0520` | `+0.0731` | `[+0.0438, +0.1041]` | `+0.0814` / `+0.0650` |
| λ=1.0 | `+0.0566` | `[+0.0271, +0.0858]` | `+0.0547` / `+0.0585` | `+0.0640` | `[+0.035, +0.095]` | `+0.0735` / `+0.0546` |

The small balanced-slice margin survives, as it did without the adversary. It is
not attributable to the adversarial term.

> **Numeric collision, not a resurrection.** The λ=1.0 prose CI lower bound
> rounds to the same value as the withdrawn Arc 1 claim "pair-coupled decoding is
> the strongest system layer (`+0.0348`)"
> (`docs/RESEARCH_INTEGRITY_REMEDIATION.md`). Unrelated quantities: that one was a
> full-population decoder-vs-unconstrained-baseline delta, withdrawn because the
> decoder received closed-world pair knowledge the baseline did not. This is a
> bootstrap interval bound on a 1,202-pair balanced-slice margin. Reported here to
> three decimals to keep the two distinguishable.

## Why this failed, and what it does and does not license

The auxiliary accuracy never reaching chance is the whole story: **polarity was
never actually removed**, so the run does not test the hypothesis it was designed
to test. This is the standard weakness of a gradient-reversal adversary — it
removes only what that particular adversary can detect. A 128-unit MLP on a
1536-dimensional vector can be evaded: the encoder can relocate polarity into
directions the head does not find while the relational head keeps using them.

Two readings remain open and this run cannot distinguish them:

1. The adversary is too weak (fix: larger/deeper aux head, multiple adversaries,
   higher λ, adversary re-initialisation, or training the aux head to convergence
   between encoder steps).
2. Polarity is not separable from the task signal at this capacity — the model
   has no content-based representation to fall back on, so removing polarity
   would remove the decision itself.

Reading 2 is consistent with everything measured so far but is **not**
established here. Do not report this run as evidence for it.

## Resolved: the adversary was too weak (reading 1)

The probe diagnostic was run — see
[POLARITY_PROBE_DIAGNOSTIC.md](POLARITY_PROBE_DIAGNOSTIC.md). A **linear** probe
on the frozen representations recovers polarity at `0.8989` (prose-native pilot,
glyph) and `0.9058` (λ=1.0, glyph), against this run's auxiliary head plateau of
`0.586` and a chance line of `0.50`.

So polarity is abundantly present and *linearly* accessible. Reading 1 holds:
the adversary never located most of what was there, and its failure says nothing
about whether removing polarity would help. Measured effect of the λ=1.0 term on
decodability: glyph `0.8989 → 0.9058` (no reduction), prose `0.8296 → 0.7950`
(`-0.035`).

Because the signal is linear, iterative nullspace projection is a better next
instrument than a larger adversary: deterministic, no λ, no minimax instability.
See the probe report for the caveat that matters — if the polarity and task
directions coincide, projection will remove the decision along with the shortcut,
so task accuracy must be reported after each projection round.

The sampling-level lever (training on the polarity-balanced distribution, ~25% of
pairs) remains untried and does not depend on an adversary winning.

## Claim boundary

Two λ values, one seed, one epoch, 1,736 prose training pairs, one backbone,
length 1024, initialised from the glyph-trained LoRA. Evaluated on 1,245 held-out
pairs across four sources with zero training overlap. The auxiliary head is not
persisted (PEFT saves adapter weights only); it exists to shape the encoder, not
for inference.
