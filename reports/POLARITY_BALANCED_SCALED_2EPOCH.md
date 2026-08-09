# Scaled Balanced Set × 2 Epochs — the epoch control

Config: `configs/research_polarity_balanced_scaled_2ep_v1.json`
Checkpoint: `checkpoints/cls_secure_code_polarity_balanced_scaled_2ep_qwen15b_lora_v1`
Artifacts: `reports/veripatch_rr_polarity_balanced_scaled_2ep_{replication,slice}.json`

Separates "more balanced data does not help" from "the scaled run only saw each
example once". 552 pairs/cell (2,208 pairs) × 2 epochs = 4,416 updates — double
the compute of both prior balanced runs, each example seen twice. Every other
setting identical. All previous artifacts unchanged.

## Verdict

**The ceiling is confirmed. The second epoch does not move discordant accuracy.**

`0.2778 → 0.2833` is `+0.0055`, well inside the spread of the four runs. What the
second epoch *does* buy is concordant accuracy, which lifts the aggregate balanced
delta to its best recorded value — but that is the model getting better at the
easy cases, not at the polarity-misleading ones.

## Four runs, one metric

Population estimator over 1,202 pairs, prose rendering:

| Run | updates | each example seen | concordant | **discordant** | balanced Δ |
| --- | ---: | ---: | ---: | ---: | ---: |
| 254/cell × 2ep, seed 7 | 2,032 | 2× | `0.8933` | `0.2778` | `+0.0856` |
| 254/cell × 2ep, seed 123 | 2,032 | 2× | `0.9051` | `0.2722` | `+0.0887` |
| 552/cell × 1ep, seed 7 | 2,208 | 1× | `0.8875` | `0.2611` | `+0.0743` |
| **552/cell × 2ep, seed 7** | **4,416** | **2×** | **`0.9168`** | **`0.2833`** | **`+0.1001`** |

Discordant accuracy across a seed change, a 2.17× data increase, and a 2× compute
increase: **`0.2611`–`0.2833`**, a spread of `0.022`. It does not respond to any
of the three levers.

Concordant accuracy *does* respond: the 1-epoch scaled run had lost ground
(`0.8875`), and the second epoch recovers it and more (`0.9168`, the best of the
four). This is why the balanced delta improves — the aggregate rises because the
concordant cell rises, not because the model handles anti-polarity pairs better.

Glyph rendering shows the same pattern: discordant `0.1889 → 0.2000`, balanced Δ
`+0.0622 → +0.0662`.

## Slice metrics

Balanced evaluation slice (308 pairs), both-directions-correct:

| Rendering | control | 254/cell × 2ep | **552/cell × 2ep** | Δ vs control | 95% CI | sign test |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| prose | `0.4968` | `0.5779` | **`0.5974`** | **`+0.1006`** | `[+0.0552, +0.1461]` | `p=3.3e-05` |
| glyph | `0.5000` | `0.5455` | `0.5584` | `+0.0584` | `[+0.0162, +0.1006]` | `p=0.0096` |

Full clean set (1,245 pairs):

| Rendering | control | 254/cell × 2ep | 552/cell × 2ep | Δ vs control | 95% CI |
| --- | ---: | ---: | ---: | ---: | --- |
| prose | `0.8273` | `0.7871` | `0.8064` | `-0.0209` | `[-0.0402, -0.0016]` |
| glyph | `0.8281` | `0.8129` | `0.8120` | `-0.0161` | `[-0.0337, +0.0016]` |

The extra compute also partly repairs the full-set cost: prose recovers from
`0.7871` to `0.8064` against the control's `0.8273`, narrowing the deficit from
`-0.0402` to `-0.0209`. Still a significant deficit.

## Conclusion: balanced sampling helps, then saturates

Confirmed. Balanced sampling reliably moves prose discordant accuracy from
`~0.19` (all non-balanced runs) to `~0.27–0.28`, and no amount of additional
balanced data or compute pushes it further. Against a `0.5` chance line the model
remains wrong on ~72% of pairs where polarity misleads.

The full ledger of interventions:

| Intervention | prose discordant | moved the decisive metric? |
| --- | ---: | --- |
| glyph-trained baseline | — (`0.1833` on glyph) | — |
| prose-native training | `0.1944` | no |
| gradient-reversal adversary, λ=0.1 / 1.0 | `0.2000` / `0.1944` | no |
| INLP, 12 rounds | `0.5056` | only by destroying the decision (`conc 0.6037`) |
| polarity-balanced, 254/cell | `0.2778` | **yes, +0.08** |
| polarity-balanced, 552/cell × 1ep | `0.2611` | no further |
| polarity-balanced, 552/cell × 2ep | `0.2833` | no further |

One lever worked, once, and saturated immediately. Everything measured since —
the probe (`0.90` linear decodability of polarity from every checkpoint), INLP
(polarity redundantly encoded across many directions), and now the flat scaling
curve — points to the same thing: **this model has no content-based relational
representation to fall back on.** Removing the shortcut's gradient relocates it to
a slightly different solution; it does not reveal a better one underneath.

## Recommendation: change approach, not scale

Further variations on sampling, adversaries, or projection are not indicated. The
remaining directions are more fundamental, and I would rank them:

1. **Capacity / backbone.** Everything here is one Qwen 1.5B LoRA classifier at
   length 1024. Whether a larger backbone, full fine-tuning, or a
   longer-context configuration has content-based features at all is untested,
   and is the cheapest way to learn whether the ceiling is the method or the
   model.
2. **Task formulation.** The candidate-identity task may be under-determined by
   a diff alone. Supplying the CWE, the surrounding file, or a build/test signal
   changes what content is available to reason over.
3. **Reporting the negative result.** Four interventions, one saturating lever,
   and a `0.90`-decodable shortcut is a coherent and well-evidenced finding about
   secure-patch benchmarks. It is a stronger contribution than any of the
   individual attempts, and it is already fully instrumented.

## Claim boundary

One run at 552/cell × 2 epochs, seed 7, prose-only training rendering, one
backbone, length 1024, initialised from the prose-native pilot. Evaluated on
1,245 held-out pairs (1,202 with defined polarity) across four sources;
balanced-slice figures rest on 308 pairs. CrossVul is training data for the
scaled checkpoints and its evaluation rows are therefore not zero-shot for them;
the 254/cell checkpoints are unaffected. The saturation conclusion covers one
doubling of data and one doubling of compute, not an extended scaling curve.
