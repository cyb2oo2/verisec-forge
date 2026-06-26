# One-Page Research Summary

Status: research artifact draft seeking external feedback. This is not yet a
formal preprint or benchmark release.

## Problem

Security patch review is not only about detecting vulnerable code; it is about
comparing a vulnerable side against a fixed side and preserving that relation
under presentation changes. Current pointwise evaluations can miss this failure
mode. A reviewer asks which side of a vulnerable/fixed pair is riskier, whether
the answer flips under an A/B side swap, and whether the evidence remains
visible under the model's tokenizer and context window.

## Core Thesis

Pointwise vulnerability accuracy is not relational patch understanding.
Side-order consistency, endpoint robustness, and runtime evidence visibility
should be measured separately.

## Method

VeriPatch-RR is a paired-diff evaluation instrument for vulnerable/fixed patch
examples. It defines relation-labeled transformations, including canonical
renderings, side swaps, suffix perturbations, and visibility-qualified context
pressure. The evaluator reports ordinary accuracy separately from side-swap
equivariance, both-directions-correct behavior, suffix consistency, and
runtime visibility.

## Main Evidence

- PrimeVul shortcut controls show that high same-source accuracy is not enough
  evidence of secure patch reasoning.
- The Qwen/CodeBERT cross-model audit separates side-order inconsistency from
  endpoint sensitivity.
- Low-canonical distilgpt2 and generative-judge slots broaden stress coverage
  without proving universal strong-model failure.
- Readout ablation, confirmation, and frozen-backbone controls show that
  endpoint robustness is controllable, while side-order reasoning remains
  unresolved.

## What This Does Not Claim

- It is not a deployed vulnerability scanner.
- It does not solve secure patch reasoning.
- It does not prove all strong models fail.
- It does not promote readout variants as better classifiers.
- It does not treat the 30-pair external smoke artifact as a model-quality
  benchmark.

## Feedback Needed

1. Is the main claim correctly bounded?
2. Is the evidence hierarchy clear enough?
3. Are the limitations strong enough for a security/ML systems audience?
4. What is the minimum next step before sharing as a preprint?

## Links

- Paper draft: `paper/draft_v0.md`
- Reviewer checklist: `docs/REVIEWER_CHECKLIST.md`
- External feedback packet: `docs/EXTERNAL_FEEDBACK_PACKET.md`
- Main results: `paper/tables/main_results.md`
- Result anchor map: `paper/result_anchor_map.md`
- External adapter: `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md`
- CI strategy: `docs/CI_TESTING_STRATEGY.md`
