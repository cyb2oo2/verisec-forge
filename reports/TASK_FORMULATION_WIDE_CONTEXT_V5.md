# Task Formulation 1: Wide Surrounding-Code Context — a negative result

Suite: `data/processed/secure_code_relational_benchmark_v5.jsonl`
(runtime `..._v5_runtime2048.jsonl`), builder `scripts/build_relational_benchmark_v5.py`
Summary: `reports/secure_code_relational_benchmark_v5_summary.json`
Configs: `configs/research_{prose_native_pilot,polarity_balanced_scaled_2ep}_qwen3b_ctx32_v1.json`
Artifacts: `reports/veripatch_rr_v5_ctx32_{slice,replication}.json`,
`reports/veripatch_rr_v5_baseline_3b_replication.json`,
`reports/veripatch_rr_v4_length_control_replication.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All narrow-context (v4)
artifacts are unchanged.

## Verdict

**Giving the model more surrounding code does not raise discordant accuracy. It
lowers it.** The primary success criterion is not met.

| Success criterion | Result |
| --- | --- |
| Discordant accuracy rises materially above the 3B ceiling (~0.42) | **failed** — `0.3889`, *below* the cap-matched baseline of `0.4389` |
| Polarity control stays near chance or is clearly surpassed on the balanced slice | met — control `0.4968`, model `+0.1494`, `p=3.81e-08` |

The formulation satisfies every design principle and still fails the decisive
test, which is what makes the result informative rather than merely negative.

## What was built

v5 changes **exactly one thing** relative to v4: the `difflib` context budget
`n`, from 3 to 32, in both rendering families. The builder asserts parity and
refuses to emit otherwise:

| Parity check vs v4 | Result |
| --- | --- |
| pair set identical | ✔ 1,245 pairs |
| polarity-balanced slice identical | ✔ 308 pairs |
| gold identical on every row | ✔ |
| exact-mirror re-validated **at the emitted width** | ✔ 0 non-mirror pairs, all four sources |

Net polarity is computed from `+`/`-` lines; context lines are emitted with a
leading space. So the control, the four `(gold × net-sign)` cells and the
balanced slice are identical to v4 **by construction**, and the measured control
accuracy confirms it: `0.5000` canonical on the balanced slice, exactly as in v4.

### Context actually delivered, per source

| Source | v4 median tok | v5 median tok | growth | truncated @2048 |
| --- | ---: | ---: | ---: | ---: |
| CrossVul | 244 | 816 | 3.3× | 10.3% |
| PrimeVul | 228 | 606 | 2.7× | 0.6% |
| PatchEval | 227 | 437 | 1.9× | 0.4% |
| **DeltaSecommits** | 278 | 280 | **1.0×** | 0.9% |

DeltaSecommits units are already fully shown at `n=3`, so it receives no new
context and functions as an **in-suite placebo**.

### Why not render the whole unit

An unbounded budget puts 31.4% of rows over 2,048 tokens (p90 = 13,979).
Truncation would then silently break the exact-mirror invariant on a third of
the suite. `n=32` holds over-length rows to the ~3% regime the published v4
suite already operates in. Measured: truncation never affects only one direction
of a pair (`one_sided = 0` on all 1,245), because mirrored renderings have
near-identical lengths.

## Decisive metric

Population estimator over 1,202 pairs with defined polarity, prose rendering.

| System | rendering suite | concordant | **discordant** | balanced Δ | 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| 3B balanced (published) | v4 @1024 | `0.8924` | `0.4333` | `+0.1629` | `[+0.1260, +0.2010]` |
| 3B balanced, **cap-matched** | v4 @2048 | `0.8992` | **`0.4389`** | `+0.1691` | — |
| 3B balanced, zero-shot wide | v5 @2048 | `0.9305` | `0.4000` | `+0.1653` | `[+0.1288, +0.2030]` |
| **3B wide-trained** | v5 @2048 | `0.9266` | **`0.3889`** | `+0.1578` | `[+0.1215, +0.1947]` |
| 3B wide prose-native (S2′) | v5 @2048 | `0.9715` | `0.1798` | `+0.0757` | — |

Glyph rendering, same checkpoints: narrow-trained `0.2167`, wide-trained
`0.1889`.

### The length control matters

Raising the cap from 1,024 to 2,048 **on the unchanged v4 rendering** moves
discordant accuracy `0.4333 → 0.4389` (prose) and `0.1944 → 0.2167` (glyph).
Part of any naive "wide context helps" reading would have been this, not
context. The correct bar for the new formulation is therefore `0.4389`, and the
wide-trained model is `-0.0500` below it.

### Dose-response, in the wrong direction

Balanced slice, prose, both-directions-correct:

| Source | context growth | narrow-trained | wide-trained | Δ |
| --- | ---: | ---: | ---: | ---: |
| **DeltaSecommits (placebo)** | **1.0×** | `0.6833` | `0.6833` | **`0.0000`** |
| PatchEval | 1.9× | `0.7237` | `0.6974` | `-0.0263` |
| PrimeVul | 2.7× | `0.6029` | `0.5882` | `-0.0147` |
| CrossVul | 3.3× | `0.6346` | `0.6250` | `-0.0096` |

The source that received no additional context is **exactly** unchanged; every
source that received context declined. The decline is caused by the
intervention, not by run-to-run noise.

### Truncation is not the cause

Restricting to the 1,203 / 1,245 pairs with no truncated row anywhere:

| System | all pairs | untruncated |
| --- | ---: | ---: |
| narrow-trained @v5 | `0.3933` | `0.3801` |
| wide-trained @v5 | `0.3820` | `0.3684` |

The ordering is preserved. (These figures use a glyph-derived polarity
assignment and so differ from the evaluator's by ~1%; the comparison is
internally consistent.)

## Required reporting

### Polarity control

| Slice | Family | control canonical | control both-correct |
| --- | --- | ---: | ---: |
| balanced (308) | prose | `0.5000` | `0.4968` |
| balanced (308) | glyph | `0.5000` | `0.5000` |
| full (1,245) | prose | `0.8321` | `0.8273` |
| full (1,245) | glyph | `0.8337` | `0.8281` |

Unchanged from v4, as the construction requires.

### Model vs control

| Slice | Family | wide-trained | Δ vs control | 95% CI | sign test |
| --- | --- | ---: | ---: | --- | --- |
| balanced | prose | `0.6461` | `+0.1494` | `[+0.0974, +0.2013]` | `p=3.81e-08` |
| balanced | glyph | `0.5714` | `+0.0714` | `[+0.0357, +0.1104]` | `p=0.000313` |
| full | prose | `0.8313` | `+0.0040` | `[-0.0161, +0.0241]` | `p=0.754` |
| full | glyph | `0.8337` | `+0.0056` | `[-0.0104, +0.0217]` | `p=0.551` |

Still comfortably above the control on the balanced slice — but *less* so than
the narrow-context model (`+0.1623`).

### Surface-form transfer

| System | glyph | prose | transfer gap |
| --- | ---: | ---: | ---: |
| control | `0.8281` | `0.8273` | `-0.0008` |
| narrow-trained | `0.8369` | `0.8337` | `-0.0032` |
| **wide-trained** | `0.8337` | `0.8313` | `-0.0024` |

Transfer remains closed. Widening context did not reintroduce glyph binding.

### Construction invariants

Exact-mirror holds at every context budget tested (3, 16, 32, 64, unbounded):
1,245/1,245. Side-swap equivariance is architecturally exact for both
antisymmetric systems on both families — the antisymmetric readout enforces it,
so it is a construction guarantee rather than a measured quantity. Single-line
rate 0.0 on all four sources.

## Why this failed — a structural reason, not a tuning problem

The decision is a **comparison between two sides**. Unchanged surrounding code
is, by definition, *identical on both sides*: it appears in the canonical and
the swapped rendering alike. Adding it therefore contributes **zero
discriminative information** to the side choice. It can only help *indirectly*,
by making the asymmetric part (the changed lines) interpretable — e.g. revealing
a buffer's declared size so that a changed bounds check can be judged.

That indirect benefit did not materialise, and the dilution cost — 2.4× more
tokens, the decision-relevant lines a smaller fraction of the input — dominated.
Concordant accuracy actually *rose* (`0.8992 → 0.9266`), which is what dilution
toward the easy majority behaviour looks like.

This generalises to a principle that governs the rest of the phase, and it is
the same one that made direction 2 a no-op before it was run:

> **Any signal that is identical on both sides cannot move the decisive metric
> on its own.** CWE, CVE, project, `cve_desc` and unchanged surrounding code are
> all pair-level and symmetric. They can only pay off by making the asymmetric
> content easier to interpret, and that payoff has now been measured once and
> found to be negative.

The remaining lever is therefore the **asymmetric** content itself — which is
what direction 3 (hard negatives / subtle content differences) manipulates, and
what direction 4 (a behavioural oracle) would have supplied.

## Direction feasibility, measured

| Direction | Status |
| --- | --- |
| 1. File/multi-hunk context | **tested, refuted** at `n=32` / 2,048 on 3B |
| 2. CWE conditioning | **no-op as specified** — CWE is already in every prompt and is symmetric across sides |
| 3. Hard-negative / contrastive pairs | feasible, now the highest-value remaining option |
| 4. Execution / test oracle | **not implementable** on this data — no source carries tests, build config or a PoC harness |

## Claim boundary

One context budget (`n=32`), one length (2,048), one backbone (3B bf16), one
seed (7), prose-only training rendering. A larger budget was rejected on
truncation grounds rather than tested, so "more context than this does not help"
is **not** established — only that 2.4× more context, at the largest width this
suite supports without breaking its own invariant, does not help. Hardware with
more than 12 GB could test `n=64`+ at 4,096 and should, before direction 1 is
considered closed. CrossVul rows are training data for the balanced checkpoints
in both arms. The decisive metric rests on 180 discordant pairs, so `0.3889` is
70/180 and the gap to `0.4389` is roughly 9 pairs — the *direction* is
corroborated by the placebo/dose-response pattern rather than by that margin
alone.

## Next

1. **Direction 3, hard-negative contrastive pairs** — the only remaining
   candidate that manipulates the asymmetric content. Mine pairs where polarity
   misleads *and* the changed-region edit distance is small.
2. **Mine more discordant pairs** (carried over from the scale-up phase, and now
   more urgent): every decisive number in this repository rests on 180 pairs,
   and the balanced training design is capped at 552/cell by the same shortage.
3. Re-test direction 1 at `n≥64` / 4,096 only on hardware that can hold it.
