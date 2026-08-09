# Prose-Native Training Pilot (v4 protocol)

Config: `configs/research_prose_native_pilot_v1.json`
Checkpoint: `checkpoints/cls_secure_code_prose_native_pilot_qwen15b_lora_v1`
Predictions: `outputs/secure_code_v4_prose_native_pilot_predictions_1024.jsonl`
Artifacts: `reports/veripatch_rr_prose_native_pilot_slice.json`,
`reports/veripatch_rr_prose_native_pilot_replication.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts are
unchanged.

## Verdict

**The pilot closes the glyph→prose transfer gap almost completely, and exceeds
both controls on the balanced slice — but it fails the decisive test. It does not
qualify as relational understanding under the stated success criterion.**

| Success criterion | Result |
| --- | --- |
| 1. Exceeds the prose control on the balanced slice | **met** (`+0.071` population estimate, CI `[+0.0425, +0.1022]`) |
| 2. Accuracy when polarity is wrong clearly above chance | **failed** (`0.1944`) |
| 3. Advantage survives the change of surface form | **met** (glyph `+0.0595`, prose `+0.0713`) |

## Training mixture

| Item | Value |
| --- | --- |
| Rendering | `split_view` prose only, `prose_fraction = 1.0` |
| Source | PrimeVul time-disjoint train split (≤2020) |
| Source pairs | 3,472 |
| Excluded — held out | 368 (all v4 suite keys plus both full PrimeVul eval pools, 2,050 keys) |
| Excluded — incomplete pair | 1,266 |
| Excluded — non-mirror | 102 |
| Excluded — flat records | 0 |
| **Training pairs / rows** | **1,736 / 3,472** |
| Init | glyph-trained baseline LoRA (see caveat) |
| Objective | antisymmetric head, 1 epoch, lr 2e-5, len 1024, seed 7 |
| Runtime | 451 s; train loss `0.679 → 0.463` |

## The transfer gap closes

Full clean set, both-directions-correct, 1,245 pairs:

| System | glyph | prose | transfer gap |
| --- | ---: | ---: | ---: |
| control | `0.8281` | `0.8273` | `-0.0008` |
| baseline antisym | `0.8000` | `0.5205` | `-0.2795` |
| repaired antisym | `0.8040` | `0.5422` | `-0.2618` |
| **prose-native pilot antisym** | **`0.8169`** | **`0.8201`** | **`+0.0032`** |

Prose performance rises from `0.5205` to `0.8201` while glyph performance is
retained (`0.8000 → 0.8169`). Against the control the pilot is now statistically
indistinguishable on **both** renderings — glyph `-0.0112` (CI
`[-0.0281, +0.0056]`), prose `-0.0072` (CI `[-0.0233, +0.0088]`) — where the
previous checkpoints were `-0.28` to `-0.31` behind on prose.

The glyph-channel binding, measured across four sources and two checkpoints, is
removed by prose-native training.

## Balanced slice (308 pairs)

| Family | System | canonical | equivariance | both-correct | delta vs control | 95% CI |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| glyph | control | `0.5000` | `1.0000` | `0.5000` | — | — |
| glyph | pilot antisym | `0.5487` | exact | `0.5487` | `+0.0487` | `[+0.0097, +0.0877]` |
| prose | control | `0.5000` | `0.9903` | `0.4968` | — | — |
| prose | **pilot antisym** | `0.5649` | exact | **`0.5649`** | **`+0.068`** | `[+0.0292, +0.1071]` |

Both intervals exclude zero, and the prose margin is the larger of the two — the
first system in this repository to exceed the control on the prose rendering.

> **Numeric collision, not a resurrection.** The prose balanced-slice delta
> rounds to the same value as the withdrawn Arc 1 claim "the detector beats a
> semantics-free control by `+0.0682`"
> (`docs/RESEARCH_INTEGRITY_REMEDIATION.md`). They are unrelated quantities: the
> withdrawn one was a full-population detector-vs-line-count margin, superseded by
> the character-level control at `+0.0008`, CI `[-0.0202, +0.0222]`. This one is a
> 308-pair balanced-slice margin over the prose control. Neither supports the
> other.

Population estimator over all 1,202 non-zero-net pairs, with disjoint-half
replication:

| Family | delta | 95% CI | 25 seed draws | half A | half B |
| --- | ---: | --- | ---: | ---: | ---: |
| glyph | `+0.0595` | `[+0.0311, +0.0891]` | 25/25 positive | `+0.0643` | `+0.0550` |
| prose | `+0.0713` | `[+0.0425, +0.1022]` | 25/25 positive | `+0.0909` | `+0.0520` |

## The decisive test fails — and shows what actually happened

| Family | acc where polarity **agrees** | acc where polarity **misleads** |
| --- | ---: | ---: |
| glyph | `0.9413` | **`0.1778`** |
| prose | `0.9481` | **`0.1944`** |

The protocol requires accuracy on anti-polarity pairs to be *clearly above
chance* before content signal may be claimed. It is `0.1944` — the model is wrong
on ~81% of the pairs where net polarity points the wrong way, essentially
unchanged from the glyph-trained baseline's `0.1833`.

**The pilot did not learn content. It relearned the same net-polarity shortcut
through the prose encoding.** `split_view` states the polarity in words
("Removed from Side A…", "Added in Side B…"), and the block sizes carry exactly
the net-character signal the `+`/`-` lines carried. Removing the glyph channel
removed one *encoding* of the shortcut, not the shortcut.

The concordant/discordant profile makes this explicit: the pilot on prose
(`0.9481` / `0.1944`) is almost identical to the baseline on glyph
(`0.9227` / `0.1833`). It is the same function, reading a different surface.

## What this establishes

1. **Transfer failure is fixable and was an encoding artifact.** The `-0.28`
   glyph→prose gap closes to `+0.0032` with 1,736 prose pairs and 7.5 minutes of
   training. The earlier collapse to chance on prose was not a capability limit.
2. **Closing it does not produce relational understanding.** Aggregate parity
   with the control on both renderings, and a positive balanced-slice margin,
   coexist with `0.19` accuracy where the shortcut fails.
3. **The protocol did its job.** Every aggregate metric in §"transfer gap" and
   §"balanced slice" reads as success. Only the conditional test in
   `docs/PURIFIED_EVALUATION_PROTOCOL.md` §3 separates "learned the task" from
   "relearned the shortcut in a new encoding".
4. **The residual asymmetry is stable but small.** `+0.0595` / `+0.0713`, 25/25
   seed draws positive, both disjoint halves positive — real, replicated, and
   still consistent with a noisy polarity follower rather than a content reader.

## Implication for the next iteration

Removing an encoding is not removing a shortcut. Any rendering that preserves
*which lines were added and which removed* preserves the net-polarity statistic,
so no rendering-level intervention can force content-based learning.

The levers that remain are at the **sampling** level, not the rendering level:

- Train on the polarity-balanced distribution itself, so the shortcut carries no
  gradient. The balanced pool is small (~25% of pairs), so this trades data
  volume for shortcut removal.
- Or add a polarity-adversarial term to the objective.

Scaling this pilot to more prose data is **not** indicated: the transfer gap it
was designed to close is already closed, and more data of the same distribution
will strengthen the same shortcut.

## Claim boundary

One pilot, one seed, one epoch, 1,736 training pairs, one backbone, length 1024,
initialised from a glyph-trained LoRA — so the starting point had already seen
unified-diff glyphs, and a from-scratch head remains the cleaner ablation.
Evaluated on 1,245 held-out pairs across four sources with zero training overlap.
Independent (non-projected) inference remains poor on prose (equivariance
`0.2940`); all balanced-slice gains are through the antisymmetric readout.
