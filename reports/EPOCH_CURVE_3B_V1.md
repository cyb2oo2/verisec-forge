# Compute Curve at 3B — where balanced training saturates

Configs: `configs/research_polarity_balanced_scaled_{3,4,6,8}ep_qwen3b_v1.json`
Checkpoints: `checkpoints/cls_secure_code_polarity_balanced_scaled_{3,4,6,8}ep_qwen3b_lora_v1`
Predictions: `outputs/secure_code_v4_polarity_balanced_scaled_{3,4,6,8}ep_predictions_1024.jsonl`
Artifacts: `reports/veripatch_rr_epoch_curve_slice.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts unchanged.

**Everything is held fixed except optimizer steps**: the published 2,208-pair
balanced set, the same 3B prose-native init, seed 7, lr 2e-5, length 1024,
LoRA r=8. Only `num_train_epochs` varies. The curve therefore measures compute
and nothing else.

## Verdict

**Discordant accuracy has not saturated by 8 epochs. The *balanced delta* has.**

Marginal gain in balanced Δ falls ~12× across the curve — `+0.0347` per epoch at
the 2→3 step, `+0.0029` per epoch at 6→8. Past the early epochs the model buys
discordant accuracy almost entirely by *selling* concordant accuracy, and the
aggregate barely moves.

**The effect is robust; the stopping point is not.** A seed replication at 4
epochs (below) moved discordant accuracy by `0.0674`, which is larger than the
gap between adjacent points on the curve. The steep-then-shallow shape and the
large 2→4+ epoch movement hold; the precise knee does not.

| Epochs | steps | concordant | **discordant** | **balanced Δ** | Δ per epoch | pure add/del | full-set prose |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 (published) | 552 | `0.8940` | `0.4326` | `+0.1633` | — | 2/28 | `0.8120` |
| 3 | 828 | `0.8567` | `0.5393` | `+0.1980` | `+0.0347` | 8/28 | `0.7968` |
| **4** | 1,104 | `0.8283` | `0.6292` | `+0.2287` | `+0.0307` | 12/28 | `0.7871` |
| 6 | 1,656 | `0.8018` | `0.6742` | `+0.2380` | `+0.0047` | 15/28 | `0.7703` |
| 8 | 2,208 | `0.7851` | **`0.7022`** | **`+0.2437`** | `+0.0029` | 17/28 | `0.7631` |

Glyph rendering — never trained on — peaks at 6 epochs and then *reverses*:
balanced Δ `+0.0881 → +0.0942 → +0.0984 → +0.1030 → +0.0934`. That turnover is
the clearest single marker of over-training on the curve.

## The trade, stated plainly

Discordant accuracy rises `+0.2696` across the curve while concordant falls
`-0.1089` and full-set prose accuracy falls `-0.0489`. Against the
semantics-free control on all 1,245 pairs:

| Slice | Family | control | 4ep | 8ep | 4ep Δ | 8ep Δ |
| --- | --- | ---: | ---: | ---: | --- | --- |
| balanced | prose | `0.4968` | `0.7273` | `0.7597` | `+0.2305` `[+0.1623, +0.2955]` | `+0.2630` `[+0.1916, +0.3312]` |
| balanced | glyph | `0.5000` | `0.5844` | `0.5812` | `+0.0844` `[+0.0422, +0.1266]` | `+0.0812` `[+0.0390, +0.1234]` |
| full | prose | `0.8273` | `0.7871` | `0.7631` | `-0.0402` `[-0.0675, -0.0120]` | **`-0.0643`** `[-0.0932, -0.0337]` |
| full | glyph | `0.8281` | `0.8394` | `0.8353` | `+0.0112` `[-0.0040, +0.0273]` | `+0.0072` `[-0.0096, +0.0241]` |

The full-set prose deficit is significant at both points and **grows** with
compute. On the population the benchmark actually samples, more epochs make the
system worse; the balanced-slice gain is a gain on a deliberately reweighted 25%
of it. Both facts are real and neither should be quoted without the other.

## Where to stop

Depends on the objective, and the curve makes the choice explicit rather than
implicit:

| Objective | Choice | Rationale |
| --- | --- | ---: |
| Best aggregate on the balanced slice | 8 epochs | `+0.2437`, but only `+0.0150` over 4ep for 2× the compute |
| Best return per unit of degradation | **3–6 epochs** | the knee lies in this range; its exact position is not resolved (see below) |
| Best on the untrained glyph rendering | 6 epochs | glyph Δ peaks and then reverses |
| Best full-set accuracy | 2 epochs | the published point; everything after trades it away |

### Seed replication at 4 epochs — the knee position is NOT resolved

Config: `configs/research_polarity_balanced_scaled_4ep_qwen3b_seed123_v1.json`.
Seed 7 → 123 for both the balanced cell draw and training.

| 4ep | concordant | discordant | balanced Δ | 95% CI | full set |
| --- | ---: | ---: | ---: | --- | ---: |
| seed 7 | `0.8283` | `0.6292` | `+0.2296` | `[+0.1922, +0.2672]` | `0.7871` |
| seed 123 | `0.8430` | `0.5618` | `+0.2036` | `[+0.1660, +0.2421]` | `0.7888` |

Discordant spread is `0.0674` — the largest seed spread recorded in this
repository (previously `0.0166` for the 3B scale-up and `0.0561` for the
hard-negative arm). The two balanced-Δ intervals overlap heavily, so the seeds
are statistically consistent with each other; what they are *not* consistent
with is a precisely located knee.

**Consequences, stated against my own earlier reading of this curve:**

- The claim "4 epochs is the knee" is **withdrawn as unresolved.** Seed 123 at
  4 epochs (`+0.2036`) is indistinguishable from seed 7 at 3 epochs (`+0.1980`).
  Adjacent points on this curve differ by less than the seed noise between them,
  so the curve's *shape* is established but its *inflection* is not.
- The 2→4 epoch movement survives easily: the worst 4-epoch seed is still
  `+0.1292` discordant above the 2-epoch point. **The compute effect is robust;
  only the stopping rule is uncertain.**
- The 6→8 increment was already flagged as inside the noise band. The 4ep
  replication widens that band, so 3, 4 and 6 epochs are now mutually
  unresolved on the aggregate.

One incidental observation: the two seeds land at different points on the same
concordant/discordant trade-off (`0.8283`/`0.6292` vs `0.8430`/`0.5618`) while
their **full-set accuracy is nearly identical** (`0.7871` vs `0.7888`). The seed
appears to determine where along the trade the model settles more than how good
it is overall.

**Operating recommendation: 3–6 epochs**, with 4 as a reasonable default on
cost grounds rather than on measured superiority. Any specific point should be
run at ≥2 seeds before its numbers are quoted.

## What this corrects

`POLARITY_BALANCED_SCALED_2EPOCH.md` concluded at 1.5B that balanced training
saturated at 2 epochs — "no amount of additional balanced data or compute pushes
it further". The 3B work inherited 2 epochs from that finding without re-testing
it.

At 3B the same setting is **badly under-trained**. The published `0.4333` sits
near the bottom of a curve that reaches `0.7022`, and the entire gap is compute
on data that already existed. Two phases of this project — the hard-negative
construction and, in part, the backbone scale-up — were interpreting points on
an unexplored compute axis as if it were flat.

It also settles the previous phase: 4 epochs on the plain balanced set
(`0.6292`) beats the hard-negative arm (`0.6067`, 3,408 pairs, seed 7) using
*less* data and no hard negatives. Hard-negative enrichment is not the lever;
it was a proxy for extra optimizer steps.

## Claim boundary

**Only the 4-epoch point is seed-replicated; 2, 3, 6 and 8 epochs are single
runs.** Measured seed spreads on the decisive metric are `0.0166` (3B scale-up),
`0.0561` (hard-negative arm) and `0.0674` (this curve's 4-epoch point). The
3→4, 4→6 and 6→8 increments are all **inside** that band, so the curve's
inflection is unresolved; only its overall steep-then-shallow shape and the
large 2→4+ movement are established.

The pure add/delete column rests on 28 evaluation pairs throughout. Its
monotone rise (2 → 17) is consistent with the main trend but is not independent
evidence.

One backbone (3B bf16), prose-only training rendering, one training set, length
1024, LoRA r=8. CrossVul rows are training data for every checkpoint on the
curve. No point on this curve has been seed-replicated, and the knee at 4 epochs
should be before it is relied on.

## Next

1. ~~Seed-replicate 4 epochs~~ — **done**; it widened rather than narrowed the
   uncertainty. Resolving the knee would need ≥3 seeds at 3, 4 and 6 epochs,
   roughly 9 runs, and is only worth it if the stopping rule matters
   operationally. The compute effect itself does not need it.
2. **Re-run the backbone comparison at 4 epochs.** The 1.5B/3B/7B scale-up was
   conducted entirely at 2 epochs, i.e. at an under-trained point for at least
   the 3B. The measured capacity gap may be larger, smaller, or differently
   shaped once each backbone is trained to its own knee.
3. **Mine more discordant pairs** — unchanged and now more pressing: the
   decisive metric rests on 180 evaluation pairs and the training design is
   capped at 552/cell by the same shortage.
