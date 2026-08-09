# INLP: Removing the Linear Polarity Direction

Script: `scripts/inlp_polarity_removal.py`
Artifact: `reports/inlp_polarity_removal.json`
Start point: frozen prose-native pilot
(`checkpoints/cls_secure_code_prose_native_pilot_qwen15b_lora_v1`), unmodified.

12 projection rounds. Each round fits a linear polarity classifier on the current
representations and projects onto the nullspace of its weight vector. Two
readouts are evaluated after every round:

* **frozen head** — the checkpoint's own `score` layer. Measures how much the
  existing decision *depended* on the removed directions.
* **retrained head** — an antisymmetric readout refit on projected *training*
  representations. Measures whether other usable signal remains. The frozen head
  cannot answer this; it has no opportunity to use anything else.

All prior checkpoints and artifacts unchanged.

## Answers to the three questions

**1. Does removing the linear polarity direction force reliance on other
signals? No.** On the prose rendering the retrained head is essentially flat
across all 12 rounds: concordant `0.9217 → 0.8982`, discordant `0.2333 → 0.2389`,
canonical `0.8186 → 0.7995`. A refit readout recovers the original
polarity-following behaviour immediately after each projection.

**2. Does accuracy when polarity is wrong rise above ~0.19? Yes for the frozen
head — but only as the decision degenerates toward random.** Prose discordant
accuracy rises `0.1944 → 0.5056`, while concordant accuracy falls
`0.9472 → 0.6037` and canonical accuracy falls `0.8344 → 0.5890` over the same
rounds. Both cells converge on `0.5` together. That is dilution toward noise, not
acquired content.

**3. Does task performance collapse together with polarity removability?
Partially — and the ordering is the real finding: the representation degrades
long before polarity is removed.** After 12 rounds the polarity probe has fallen
only `0.8589 → 0.7996`, while the retrained glyph head has already collapsed to
chance (`0.5740` canonical, `0.5222` discordant). Projection damages the
representation faster than it removes polarity.

## Frozen head

| round | polarity probe | glyph conc | glyph disc | glyph canonical | **glyph balanced Δ** | prose conc | prose disc | prose canonical | **prose balanced Δ** |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | `0.8589` | `0.9403` | `0.1778` | `0.8261` | `+0.0590` | `0.9472` | `0.1944` | `0.8344` | `+0.0708` |
| 4 | `0.8317` | `0.9276` | `0.1833` | `0.8161` | `+0.0555` | `0.9110` | `0.2500` | `0.8120` | `+0.0805` |
| 8 | `0.8142` | `0.8836` | `0.1833` | `0.7787` | `+0.0334` | `0.7162` | `0.4167` | `0.6714` | `+0.0665` |
| 12 | `0.7996` | `0.8376` | `0.2222` | `0.7454` | `+0.0299` | `0.6037` | `0.5056` | `0.5890` | `+0.0546` |

## Retrained head

| round | glyph conc | glyph disc | glyph canonical | **glyph balanced Δ** | prose conc | prose disc | prose canonical | **prose balanced Δ** |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | `0.9276` | `0.2167` | `0.8211` | `+0.0721` | `0.9217` | `0.2333` | `0.8186` | `+0.0775` |
| 4 | `0.9237` | `0.2222` | `0.8186` | `+0.0730` | `0.9119` | `0.2611` | `0.8145` | `+0.0865` |
| 8 | `0.8806` | `0.2722` | `0.7895` | `+0.0764` | `0.9100` | `0.2333` | `0.8087` | `+0.0717` |
| 12 | `0.5832` | `0.5222` | `0.5740` | `+0.0527` | `0.8982` | `0.2389` | `0.7995` | `+0.0686` |

## The invariant that explains everything

**The balanced delta does not move.** Across 12 rounds, two renderings and two
readouts, it stays in `+0.024` to `+0.089` — the same band as the unprojected
model (`+0.0595` / `+0.0713` in
`reports/VERIPATCH_RR_BALANCED_SLICE_REPLICATION.md`). Concordant and discordant
accuracy swing enormously; their balanced average does not.

This is the cleanest available statement of what the residual signal is:

* it is **not** the linear polarity direction — projecting that direction out
  repeatedly does not remove it;
* it is **not convertible into anti-polarity competence** — every rise in
  discordant accuracy is paid for one-for-one by a fall in concordant accuracy;
* it is **stable** — it survives 12 projections, head retraining, and both
  renderings, and it never grows.

A decision that moves toward random raises discordant accuracy toward `0.5`
mechanically. That is why the decisive metric must always be read beside
concordant accuracy: `disc = 0.5056` at round 12 looks like the target
(`≫ 0.25–0.30`) but arrives with `conc = 0.6037`, i.e. a system that has lost
most of its accuracy rather than gained any understanding.

## Why INLP does not work here

Polarity is **highly redundant**, not a single direction. Twelve nullspace
projections reduce probe accuracy by only `0.059` (`0.8589 → 0.7996`). Reaching
chance would take many more rounds, and the retrained glyph head is already at
chance by round 12. There is no round at which polarity is removed and the task
survives.

Combined with `reports/POLARITY_PROBE_DIAGNOSTIC.md` — where polarity was
linearly decodable at `0.90` — the picture is that polarity is linearly
*readable* from many directions simultaneously, so removing any one of them
leaves the rest intact while costing representational capacity.

## Consequence for the programme

Three representation-level interventions have now failed to produce content-based
relational signal, each for a measured reason:

| Intervention | Outcome | Measured reason |
| --- | --- | --- |
| Prose-native training | transfer gap closed, decisive metric unchanged | shortcut relearned through the prose encoding |
| Gradient-reversal adversary | no change at either λ | adversary found `0.586` of a `0.90` signal |
| INLP | task degrades before polarity is removed | polarity is redundant across many directions |

The common cause is that net polarity is not a removable feature of the
*representation* — it is a property of the **data**, present in every rendering
that reveals which lines were added and removed, and recoverable from many
directions at once.

That leaves the sampling-level lever, which is the only one that attacks the
correlation rather than its encoding: **train on the polarity-balanced
distribution**, where the shortcut carries no gradient because the four
(gold × net-sign) cells are equal. It costs ~75% of the training pairs and has not
been tried.

## Claim boundary

One start checkpoint, 12 rounds, one probe family (linear, polarity *sign* not
magnitude), one pooling site (terminal token), 1,202 evaluation pairs across four
sources, one seed. INLP was applied to cached representations; no checkpoint was
modified, and the projected representation was never written back into a model.
Failure of these three interventions does not establish that no intervention can
work.
