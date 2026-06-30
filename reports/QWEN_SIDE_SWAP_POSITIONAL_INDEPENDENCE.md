# Qwen Side-Swap Positional Independence

`reports/QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md` establishes that
endpoint-collapse repair and side-swap equivariance are largely separable
failure modes. This report goes one level deeper: what does the side-swap
failure actually consist of? Reusing the same predictions (no new GPU
inference), it tests whether the model's prediction under side-swap still
tracks the underlying code content (just mislabeled), or whether it is
closer to content-blind under swap, falling back to a positional prior.

## Method

For each of the 600 base pairs, compare the predicted side under `canonical`
against the predicted side under three other conditions, using a 2x2
contingency table (chi-square test of independence, n=600 each) and the phi
correlation coefficient.

## Results

| Comparison | A-rate (canonical) | A-rate (other) | chi2 (1 df) | phi | p |
| --- | ---: | ---: | ---: | ---: | ---: |
| `canonical` vs `padding_post_diff_terminal_phrase` (no swap) | 0.613 | 0.585 | 380.97 | `+0.797` | `<0.0001` |
| `canonical` vs `side_swap` | 0.613 | 0.602 | 0.34 | `-0.024` | `0.559` |
| `canonical` vs `side_swap` + terminal phrase | 0.613 | 0.585 | 4.37 | `-0.085` | `0.037` |

Two further facts anchor the interpretation:

- **Gold is balanced**: 48.3% of the 600 pairs have side A as the true
  vulnerable side, 51.7% side B. The model's ~60-61% "predict A" marginal
  rate does not track the true label distribution -- it is not a learned
  base-rate shortcut that happens to be correct.
- **Canonical accuracy (66.00%) is well above the "always predict A"
  baseline (48.33%, the gold A-rate)**, so the model is not simply
  outputting a fixed answer; under the canonical (un-swapped) presentation
  it does extract real, accuracy-relevant signal from content.

## Interpretation

The non-swap comparison (padding only, same physical position) shows a
strong, expected positive correlation (`phi = 0.80`): predictions are
content-preserving when the candidate stays in its original "Side A" / "Side
B" slot. The swap comparison shows a phi coefficient indistinguishable from
zero (`phi = -0.024`, `p = 0.56`) -- canonical and swapped predictions for
the *same underlying pair* are statistically independent draws. Adding the
terminal phrase to the swap condition nudges this to a small but detectable
negative correlation (`phi = -0.085`, `p = 0.037`), consistent with the
small-but-real interaction effect already found in the companion report,
without changing the qualitative picture.

This sharpens "side-order reasoning remains unresolved" into a more precise
mechanistic claim: the failure is not best described as "the model gets
confused about which side is which." It is closer to **content-blindness
specifically triggered by the swap** -- when a candidate moves from the
"Side A" slot to the "Side B" slot, the model's prediction for that slot
reverts to something close to a fixed marginal preference (~60% "A"), rather
than re-evaluating the same content it could evaluate accurately in the
original slot. Combined with the strong non-swap correlation (the model
*can* use content when position is held fixed), this points toward
position-specific rather than content-symmetric processing as the locus of
the failure -- exactly the architectural target the project's own roadmap
already names (`paper/outline.md`: "whether model architectures or
objectives can enforce side-order structure, such as antisymmetric pair
scoring").

## Claim Boundary

This is an observational, correlational analysis on existing predictions
from one checkpoint, one length setting (1024), 600 pairs. It establishes
statistical independence between canonical and swapped predictions; it does
not identify *which* internal mechanism (attention pattern, positional
embedding, learned per-slot features) causes the position-specific
processing, and it does not test or propose an architectural fix. The
~60% "predict A" marginal is observed, not explained -- this report does not
establish why the model favors A over B at that specific rate, only that
the rate is stable across canonical and swapped conditions and untethered
from the true (balanced) label distribution.
