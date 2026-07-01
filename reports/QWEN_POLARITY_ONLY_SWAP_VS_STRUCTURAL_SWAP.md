# Qwen Polarity-Only Swap vs. Structural Swap

`reports/QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` swapped **only the
"Side A" / "Side B" text labels** (holding the diff hunk body byte-for-byte
fixed) and found the prediction barely moved (`phi = +0.914` vs. canonical):
the model does not key off the prose labels. That report named its own
complement as future work -- flip the **diff hunk polarity** while holding the
labels fixed -- because no condition there disturbed polarity. This report
runs exactly that complement, completing the 2x2 decomposition of the
`swap_pair()` intervention into its label and polarity factors.

## Method

`scripts/build_qwen_mechanism_polarity_only_swap_audit.py` builds
`polarity_only_swap`, the mirror image of `label_only_swap`:

- Start from the already-reverse-rendered `canonical_renderer_swap_v2` text.
  `swap_pair()` exchanged `side_a`/`side_b` and regenerated the whole diff via
  `difflib`, so this text already has the **flipped polarity** (canonical
  `-side_a`/`+side_b` becomes `-side_b`/`+side_a`) -- but it also moved the
  label->content binding and flipped the gold.
- Apply `label_only_swap` (the pure "Side A" <-> "Side B" word substitution
  from the prior report) to relabel the words back, so "Side A" again denotes
  the canonical `side_a` content. This restores the label meaning **and the
  gold answer** while leaving the flipped `-`/`+` body byte-for-byte intact.

Net effect vs. canonical: the only thing that changes is diff hunk polarity /
structural content order -- which content is removed (`-`) vs. added (`+`),
and the from->to direction. The words "Side A"/"Side B" denote the same code
they did canonically and `gold_riskier_side` is **unchanged**, so a
content-tracking model should be invariant (same answer as canonical) and any
prediction change is attributable to the polarity flip alone.

Because its diff body is byte-identical to `side_swap` and differs only in the
(now-established-inert) label words, `polarity_only_swap` re-expresses the
structural swap with the gold restored to the content-correct answer. The
plain `side_swap` variant is re-derived on the same 600 pairs so all three
conditions are compared on identical underlying pairs.

- Checkpoint: `checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1`
  (same as the prior three reports in this line)
- Length: 1024
- 600 base pairs, 1,800 rows (`canonical`, `polarity_only_swap`, `side_swap`)
- `transformation_introduced_critical_truncation_rows: 0` for all variants

## Results

| Comparison | n | A-rate (canonical) | A-rate (other) | chi2 | phi | p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| canonical vs `polarity_only_swap` (polarity flipped, labels/gold fixed) | 600 | 0.613 | 0.655 | 5.29 | `-0.094` | `0.021` |
| canonical vs `side_swap` (labels + polarity both swapped) | 600 | 0.613 | 0.602 | 0.34 | `-0.024` | `0.559` |
| canonical vs `label_only_swap` (labels swapped, polarity fixed; from prior report) | 600 | 0.613 | 0.655 | 501.29 | `+0.914` | `<0.0001` |

| Variant | Accuracy |
| --- | ---: |
| `canonical` | 0.6600 |
| `polarity_only_swap` (gold = canonical) | 0.3450 |
| `side_swap` (gold flipped) | 0.6650 |

Cross-check -- `polarity_only_swap` vs. `side_swap` predictions (byte-identical
diff bodies, differ only in the "Side A"/"Side B" words):

| Comparison | n | agree | phi | p |
| --- | ---: | ---: | ---: | ---: |
| `polarity_only_swap` vs `side_swap` | 600 | 568 / 600 (`0.947`) | `+0.892` | `<0.0001` |

## Interpretation

Flipping the diff hunk polarity moves the prediction: `polarity_only_swap`
agrees with canonical on only `295/600` pairs (`phi = -0.094`, `p = 0.021`),
near statistical independence -- the **opposite behavior** from
`label_only_swap`, where relabeling left the prediction frozen (`phi = +0.914`,
agreement `575/600`). The two interventions differ only in which factor they
disturb, so the contrast localizes the driver: the model's side decision
tracks **diff hunk polarity (structural content order), not the prose text
labels**.

The accuracy makes the harm concrete. `polarity_only_swap` holds the gold
answer fixed at the canonical value -- "Side A" still denotes the same code and
the same side is still riskier -- yet accuracy collapses from `0.6600` to
`0.3450`. Of the `396` pairs the model classifies correctly under the canonical
rendering, `247` (`62%`) flip to the wrong answer when the identical comparison
is rendered as a reverse diff. The model is answering from the polarity of the
hunk, not from which code is actually vulnerable.

The cross-check pins the attribution. `polarity_only_swap` and `side_swap` have
byte-identical diff bodies and differ only in the "Side A"/"Side B" words; their
predictions agree on `568/600` pairs (`phi = +0.892`), independently
reproducing the prior report's finding that the words are inert. So the
`0.665` accuracy against the flipped gold (`side_swap`) and the `0.345`
accuracy against the content-preserved gold (`polarity_only_swap`) come from
the **same predictions on the same diff bodies** -- the shared prediction
scores well when the gold is flipped to follow the reversed diff and poorly
when the gold is held to the content-correct answer, i.e. the decision follows
the hunk polarity rather than which code is actually vulnerable. The `side_swap` reproduction
(`phi = -0.024`, matching the independence report exactly) confirms the three
conditions run on the same pairs.

Combined with the prior report, the 2x2 is complete: relabeling alone does not
move the prediction; flipping polarity alone does. Whatever drives the
side-swap failure is tied to the structural diff representation -- which
content occupies the removed vs. added lines -- not the prose framing around it.

## Claim Boundary

This report directly confirms hunk-polarity sensitivity that the prior report
could only point to: a polarity flip with labels and gold held fixed moves the
prediction to near-independence and collapses accuracy, while pure relabeling
does neither. It does not identify *why* polarity drives the decision (e.g., a
specific positional or removed-line prior), nor does it show the effect is a
clean inversion -- `phi = -0.094` is decorrelation, not `-1`, consistent with
the content-blindness characterization from the independence report rather than
a deterministic sign flip. One checkpoint, one length, 600 pairs,
observational/correlational only.
