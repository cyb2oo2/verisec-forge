# Qwen Label-Only Swap vs. Structural Swap

`reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md` shows that canonical and
fully-side-swapped predictions for the same pair are statistically
independent (`phi = -0.024`). That swap (`swap_pair()` in
`src/vrf/relational_benchmark.py`) changes two things simultaneously:
the **header text labels** ("Side A" / "Side B" in the instructions and
diff markers) and the **diff hunk polarity** (which content generates the
`-` removed lines vs. the `+` added lines -- `swap_pair()` exchanges
`pair.side_a`/`pair.side_b` before re-running `difflib.unified_diff`, so the
whole diff is regenerated with reversed polarity, not just relabeled).

This report decouples them: it swaps **only the header text labels**,
leaving the diff body's `-`/`+` lines byte-for-byte identical, to test
which of the two factors the model's prediction actually tracks.

## Method

`scripts/build_qwen_mechanism_label_only_swap_audit.py` performs a pure
string substitution of "Side A" <-> "Side B" throughout the canonical
prompt (the "Unified diff from Side A to Side B:" header sentence and the
"--- Side A" / "+++ Side B" diff markers -- the only three occurrences in
the canonical renderer). The diff hunk body is untouched. `gold_riskier_side`
is flipped to match the new labels (the same underlying content is now
called by the other letter).

- Checkpoint: `checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1`
  (same as the prior two reports in this line)
- Length: 1024
- 600 base pairs, 1,200 rows (`canonical`, `label_only_swap`)
- `transformation_introduced_critical_truncation_rows: 0` for both variants

## Results

| Comparison | n | A-rate (canonical) | A-rate (other) | chi2 | phi | p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| canonical vs `label_only_swap` (labels swapped, content/polarity fixed) | 600 | 0.613 | 0.655 | 501.29 | `+0.914` | `<0.0001` |
| canonical vs `side_swap` (labels + polarity both swapped, from `QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`) | 600 | 0.613 | 0.602 | 0.34 | `-0.024` | `0.559` |

| Variant | Accuracy |
| --- | ---: |
| `canonical` | 0.6600 |
| `label_only_swap` | 0.3483 |

## Interpretation

Under a pure label relabeling, the predicted side barely moves at all
(`phi = 0.91`, near-perfect positive correlation) -- the classifier outputs
almost the same answer as canonical, regardless of which text label is
attached to which content. Accuracy collapses to `0.3483`, almost exactly
`1 - 0.66`: consistent with the prediction staying essentially frozen while
`gold_riskier_side` flips underneath it (because gold tracks the true
labeled side, which the model evidently does not).

This rules out the simplest version of a "literal text label" bias -- the
model is not keying off the words "Side A" / "Side B" in the prompt. Since
the only other factor `swap_pair()` changes is diff hunk polarity (which
content produces `-` vs `+` lines), and that factor is exactly the one held
fixed here, the most consistent explanation is that the classifier's
decision substantially tracks **diff hunk polarity / structural content
order**, not the textual side labels. Combined with the prior independence
result under full swap (where both factors move together and the
correlation collapses to ~0), the picture is: relabeling alone barely
matters; whatever does drive the side-swap failure is tied to the
structural diff representation itself, not the prose framing around it.

## Claim Boundary

This report establishes that text-label relabeling alone does not explain
the side-swap failure -- it does not yet directly confirm hunk-polarity
sensitivity, since no condition here flips polarity while holding labels
fixed (the complementary experiment to this one). It is consistent with,
but does not prove, a hunk-polarity-driven mechanism; ruling out the label
hypothesis narrows the explanation space without yet completing it. One
checkpoint, one length, 600 pairs, observational/correlational only.
