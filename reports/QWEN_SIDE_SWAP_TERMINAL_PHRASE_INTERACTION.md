# Qwen Side-Swap x Terminal-Phrase Interaction Audit

`reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md` establishes two separate facts
about the same checkpoint: side-swap equivariance is near chance (48.50% at
1024 tokens), and a terminal completion phrase repairs endpoint-collapse
invariance from 42.67% to 90.50%. Those two interventions were never tested
**in combination** -- the existing benchmark has no
`padding_post_diff_terminal_phrase_side_swap` variant. This audit closes
that gap: does the fix for endpoint collapse also repair side-swap
equivariance, or are they independent failure modes?

## Protocol

- Checkpoint: `checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1`
  (same checkpoint as `QWEN_RELATIONAL_MECHANISM_AUDIT.md`)
- Length: `1024` tokens (the setting where the terminal-phrase repair is
  strongest in the original audit)
- Base pairs: `600` (same `representative`/`identity` rows as the original
  audit: PrimeVul, DeltaSecommits, PatchEval)
- Four variants per pair, built by reusing the existing
  `padding_variants()` helper applied to side-swapped text instead of
  canonical text: `canonical`, `side_swap`, `padding_post_diff_terminal_phrase`,
  `side_swap_padding_post_diff_terminal_phrase`
- `transformation_introduced_critical_truncation_rows: 0` for all four
  variants -- the result below is not a truncation artifact

## Results

| Variant | n | Canonical-label accuracy | Relation accuracy |
| --- | ---: | ---: | ---: |
| `canonical` | 600 | 0.6600 | n/a |
| `side_swap` | 600 | 0.6650 | 0.4883 (equivariance) |
| `padding_post_diff_terminal_phrase` | 600 | 0.6517 | 0.9017 (invariance) |
| `side_swap_padding_post_diff_terminal_phrase` | 600 | 0.6783 | 0.5217 (equivariance) |

The `side_swap` and `padding_post_diff_terminal_phrase` rows replicate the
original audit's headline numbers (48.50%/90.50%) closely on this 600-pair
subset, confirming the new dataset construction is consistent with the
established result.

## The Interaction

| Condition | Equivariance | Delta from `side_swap` alone |
| --- | ---: | ---: |
| `side_swap` (no terminal phrase) | 0.4883 | -- |
| `side_swap` + terminal phrase | 0.5217 | `+0.0333` |

Paired McNemar test over the same 600 pairs (repaired: 39, introduced: 19,
discordant: 58): **p = 0.0119**. The bump is statistically significant but
the effect size is roughly 14x smaller than the terminal phrase's effect on
the invariant-endpoint case (`+0.4783`, from 42.67% to 90.50% in the
original audit).

## Interpretation

The terminal-phrase intervention overwhelmingly repairs the
invariant-endpoint failure mode and only marginally, though measurably,
affects side-swap equivariance. This is direct, well-powered evidence
(n=600, not a small pilot) that **side-order reasoning and endpoint
sensitivity are largely separable failure modes**, not two symptoms of one
underlying mechanism. A fix that makes the model robust to where the diff
ends in the prompt does not transfer to making it robust to which physical
position ("Side A" vs "Side B") a candidate occupies.

This directly answers the question left open by treating the two
interventions separately in the original audit: it was not yet established
whether the endpoint-collapse mechanism explained part of the side-swap
failure too. It does not -- the two are close to orthogonal, with only a
small, statistically detectable but practically negligible shared
component.

## Claim Boundary

This is one checkpoint, one length setting (1024), one specific pair of
interventions crossed. It does not test whether other endpoint-repair
mechanisms (different terminal phrases, different pooling strategies)
would interact differently with side-swap equivariance, and it does not
itself propose or test an architectural fix for side-order reasoning. It
narrows the search space for one: whatever mechanism causes side-swap
failure is evidently not the same mechanism the terminal-phrase
intervention addresses, so an architectural fix for side-order reasoning
should not be expected to fall out of further endpoint-robustness work.
