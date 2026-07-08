# External Review Request

Status: working-draft request for feedback. This is not a submission-ready
packet, a preprint, or a claim that the draft is finished.

## Project Summary

VeriSec Forge studies whether secure-code models that look competent under
pointwise vulnerability classification actually preserve the vulnerable/fixed
relation when a patch pair's presentation changes. Using VeriPatch-RR, a
paired-diff evaluation instrument, we find that a model's riskier-side
decision can be nearly inert to swapping the prose Side A / Side B labels
while highly sensitive to flipping diff-hunk polarity with the gold answer
held fixed, and this behavioral ordering replicates across a Qwen decoder
classifier and a competency-matched CodeBERT encoder classifier. We also
measure a confound where an external dataset (CrossVul) shows higher raw
accuracy that tracks a stronger presentation shortcut rather than better
reasoning, and we test a structural antisymmetric repair that holds as a
constraint while a learned fine-tuning version built on top of it does not
transfer.

## What To Read First (5-10 Minutes)

1. `docs/ONE_PAGE_RESEARCH_SUMMARY.md` -- the shortest framing.
2. `paper/draft_v0.md` -- Abstract, Section 3 (task boundary), Sections 6.3-6.4,
   Section 8, and Limitations (Section 9).
3. `paper/tables/main_results.md` and Tables 2-4 in the draft.
4. `paper/result_anchor_map.md` -- every numeric result traced to a report.
5. `docs/EXTERNAL_FEEDBACK_PACKET.md` -- the reviewer-facing claim table and
   specific questions.

## What Feedback Is Being Requested

- Is the main thesis (pointwise accuracy can hide relation-violating
  behavior) framed at the right strength -- too broad, too narrow, or
  correctly bounded?
- Is the distinction between competency-controlled evidence (Qwen, CodeBERT)
  and low-canonical stress evidence (distilgpt2, the small generative judge)
  clear enough?
- Are the readout-mechanism and CrossVul-confound claims convincing without
  overclaiming?
- Are the limitations (Section 9) strong enough for a security/ML-systems
  audience?
- What is the minimum next step before this becomes a preprint?

## What This Work Does Not Claim

- It does not solve secure patch reasoning.
- It does not show that all strong secure-code models fail; there is no
  universal-failure claim.
- It is not a proof of a shared internal mechanism across architectures --
  the Qwen/CodeBERT replication is behavioral evidence, not a mechanistic
  proof.
- It does not claim that CrossVul's higher raw accuracy demonstrates
  stronger secure-code reasoning; the confound measurement points the other
  way.
- The antisymmetric readout is a structural constraint; the learned
  fine-tuning repair built on top of it is not validated -- it failed
  transfer to CrossVul and to four of five nuisance-transform families.
- It is not a deployed vulnerability scanner and does not replace human
  security review.
- It is not being represented as ready for top-conference submission; it is
  a working draft seeking feedback before that stage.

## Known Limitations

- Human adjudication of evidence localization is at diagnostic scale
  (`n=20`), not a general validation set; AI-filled adjudication supplements
  it but is explicitly not independent human gold.
- Model-family coverage is two competency-matched architectures (Qwen
  decoder, CodeBERT encoder) plus two low-canonical secondary slots
  (distilgpt2, a small generative judge) -- broader than one model, but not a
  claim of universality.
- The frozen-backbone mechanism result is conditional on a single
  terminal-seed7 Qwen+LoRA representation.
- Citation coverage for the external datasets and model backbones was closed
  in PR #67, but the reference list is still anchor-based (`[RELATED: ...]`)
  rather than a fully formatted bibliography.

## Links

- Paper draft: `paper/draft_v0.md`
- References: `paper/references.md`
- Result anchor map: `paper/result_anchor_map.md`
- External feedback packet: `docs/EXTERNAL_FEEDBACK_PACKET.md`
- PhD / top-lab application readiness audit:
  `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`
- One-page research summary: `docs/ONE_PAGE_RESEARCH_SUMMARY.md`
- Main results table: `paper/tables/main_results.md`
- Key figures: `paper/figures/figure1_problem.svg`,
  `paper/figures/figure5_label_polarity_mechanism.svg`,
  `paper/figures/figure6_crossvul_confound.svg`,
  `paper/figures/figure7_repair_decomposition.svg`
- Email templates for sending this request: `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`

## How To Send Feedback

Reply directly, or use the format in `docs/EXTERNAL_PARTICIPATION_GUIDE.md`:

```text
Section or file:
Concern:
Why it matters:
Suggested fix:
```
