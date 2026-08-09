# Polarity Probe on Frozen Encoders

Script: `scripts/probe_polarity_representation.py`
Artifact: `reports/polarity_probe_diagnostic.json`

Settles the open question in `reports/POLARITY_ADVERSARIAL_V1.md`: the
gradient-reversal adversary's auxiliary head plateaued at `0.586` polarity
accuracy, consistent with either (1) the adversary being too weak, or (2)
polarity already being absent or inseparable from the task signal.

**Answer: reading (1). Polarity is abundantly present — and it is linearly
decodable at up to `0.906`. The adversary was far too weak.**

No checkpoint was modified; representations were extracted under `no_grad` and
probes fit on cached vectors. All prior artifacts unchanged.

## Setup

| Item | Value |
| --- | --- |
| Pooling | last non-pad position of the final hidden layer (matches the relational head) |
| Target | sign of the pair's net character change, mirrored for swap renderings |
| Rows with a defined label | 4,808 / 4,980 (zero-net pairs excluded) |
| Split | **pair-disjoint**: 841 train pairs / 361 val pairs |
| Rows per family | 1,682 train / 722 val |
| Val positive rate | `0.5000` (chance is exactly 0.5) |
| Probes | linear; and MLP 1536→512→256→1, ReLU, dropout 0.1 |
| Optimisation | AdamW, lr 1e-3, weight decay 1e-4, 400 full-batch epochs |

## Peak validation accuracy

| Checkpoint | family | linear | MLP |
| --- | --- | ---: | ---: |
| glyph baseline | glyph | `0.8947` | `0.8864` |
| glyph baseline | prose | `0.6925` | `0.7133` |
| prose-native pilot | glyph | `0.8989` | `0.8975` |
| prose-native pilot | prose | **`0.8296`** | `0.8296` |
| adversarial λ=1.0 | glyph | **`0.9058`** | `0.8961` |
| adversarial λ=1.0 | prose | `0.7950` | `0.7992` |

Probes converged rather than underfit: MLP train accuracy reaches 99.8–100% in
every cell, and the linear probe reaches 92–95% train.

## Four findings

**1. Polarity is abundantly present — well above the adversary's reach.**
`0.83–0.91` against a chance line of `0.50`, versus the GRL auxiliary head's
`0.586`. The adversary recovered a small fraction of what a probe finds, so it
could not have removed what it never located.

**2. The λ=1.0 adversary did essentially nothing.** On the glyph rendering,
polarity decodability *rose* slightly, `0.8989 → 0.9058`. On prose it fell
`0.8296 → 0.7950`, a `-0.035` reduction. That is the entire measurable effect of
the adversarial term — and it is consistent with the decisive metric being
unchanged to four decimals in `POLARITY_ADVERSARIAL_V1.md`.

**3. Polarity is *linearly* decodable.** The linear probe matches or beats the
512-unit MLP in five of six cells. This makes the GRL failure more damning — a
linear direction is the easiest possible target — and it makes removal tractable
by construction rather than by adversarial search.

**4. Prose-native training made prose-polarity *more* decodable.** On the prose
rendering: glyph baseline `0.6925` → prose-native pilot `0.8296`, a `+0.137`
increase. This is direct representational corroboration of the behavioural
finding in `PROSE_NATIVE_PILOT_V1.md`: training on prose did not teach content,
it taught the model to read polarity out of the prose block sizes. The
representation now encodes prose polarity nearly as well as glyph polarity.

## What this licenses

Building a stronger adversary is **justified**: there is a large, linearly
accessible polarity signal to remove, and the previous run demonstrably failed to
remove it rather than demonstrating that removal is impossible.

The linear finding suggests a more direct method than adversarial search:
iterative nullspace projection (INLP) — fit a linear polarity classifier, project
the representation onto its nullspace, repeat until polarity is at chance. That is
deterministic, has no λ to tune, and no minimax stability problem. Its risk is the
one this diagnostic cannot settle: if the polarity direction and the task
direction substantially coincide, projecting out polarity will also destroy the
decision. The `0.1778–0.1944` anti-polarity accuracy measured throughout suggests
they may largely coincide, so an INLP run should report task accuracy after each
projection round, not only at the end.

The sampling-level lever (training on the polarity-balanced slice) remains
independent of all of this and untried.

## What this does not license

This measures *decodability*, not *use*. A probe recovering polarity at `0.90`
does not prove the relational head reads that direction, and removal of a
decodable direction does not guarantee behavioural change. The claim here is
narrow: the adversary's `0.586` was far below what was available, so its failure
is uninformative about whether polarity removal would help.

## Claim boundary

Three checkpoints, one pooling site (terminal token), one target (polarity sign,
not magnitude), 1,202 pairs across four sources, length 1024, one seed, one
pair-disjoint split. Probes were not tuned per checkpoint; a stronger probe or a
different pooling site could recover more. All accuracies are therefore lower
bounds on the polarity information present.
