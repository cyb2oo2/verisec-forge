# External Feedback Packet

This packet is for external reviewers who can spend 5-10 minutes assessing the
research claim, evidence hierarchy, and preprint readiness of VeriSec Forge /
VeriPatch-RR. It is not a new result, benchmark release, or application packet.

## 1. One-Paragraph Summary

VeriSec Forge studies whether secure-code models that appear competent under
pointwise vulnerability detection preserve the vulnerable/fixed relation under
paired patch transformations. The central finding is that pointwise secure-code
accuracy can hide relation-violating behavior induced by patch presentation
structure: a model's riskier-side decision is nearly inert to swapping the prose
Side A / Side B labels but highly sensitive to flipping diff-hunk polarity with
the gold answer held fixed. This behavioral ordering replicates across a Qwen
decoder classifier and a competency-matched CodeBERT encoder classifier (a
cross-architecture behavioral phenomenon, not a proven shared internal
mechanism), external-source (CrossVul) canonical accuracy is inflated by a
stronger presentation shortcut, and a hard antisymmetric readout is a
transferable structural consistency constraint while the learned fine-tuning
repair over it is not validated. VeriPatch-RR is a measurement and mechanism
study, not a deployed vulnerability scanner.

## 2. Draft Status (for the reviewer)

- Appendices A–E are complete; no `[APPENDIX PLACEHOLDER]` remains.
- Main-text Tables 2–4 (mechanism, CrossVul confound, repair) and Figures 5–7
  (deterministic SVGs from committed report JSON) are in place.
- No must-run experiment is pending: the two must-run evidence gaps (CrossVul
  polarity/gold confound; competency-matched CodeBERT replication) are done.
- **Remaining gaps are citation polish and optional future work**, not evidence
  gaps. See `paper/references.md` "Citation Gaps" for the sources (CrossVul,
  DeltaSecommits, PatchEval, Qwen2.5-Coder, distilgpt2) still marked
  `citation needed`. This is a working draft, not a final submission.

## 3. Five-Minute Reading Path

1. `README.md`
2. `paper/draft_v0.md` Abstract, §3 (task boundary), §6.3–6.4, §8, and Limitations
3. `paper/tables/main_results.md` and Tables 2–4 in the draft
4. `paper/result_anchor_map.md`
5. `docs/REVIEWER_READINESS_AUDIT.md`

## 4. Claims I Want Feedback On

| Claim | Current Evidence | Feedback Needed |
| --- | --- | --- |
| Pointwise secure-code accuracy can hide relation-violating behavior induced by patch presentation structure. | VeriPatch-RR relation tests; label-only vs polarity-only decomposition (§6.3). | Is the claim framed at the right strength? |
| The label-vs-polarity ordering replicates across Qwen and CodeBERT, but the functional form differs — a behavioral phenomenon, not a shared internal mechanism. | CodeBERT competency-matched replication + crude-shortcut agreement (Table 2, Figure 5). | Is the behavioral-vs-internal boundary clear enough? |
| CrossVul raw canonical accuracy is not standalone evidence of stronger reasoning. | CrossVul confound measurement (Table 3, Figure 6). | Is the confound caveat convincing? |
| The antisymmetric readout is a structural constraint; the learned fine-tuning repair is not validated. | Repair decomposition + transfer failures (Table 4, Figure 7). | Is the structural-vs-learned split stated correctly? |

## 5. What This Work Does Not Claim

- It is not a deployed vulnerability scanner.
- It does not solve secure patch reasoning.
- It does not prove all strong models fail (no universality claim).
- It does not claim a shared internal mechanism across architectures.
- It does not claim CrossVul accuracy proves stronger reasoning.
- It does not claim a validated learned repair.
- It does not treat the external 30-pair smoke artifact as a model-quality
  benchmark.
- It does not replace human security review.

## 5. Specific Reviewer Questions

1. Is the main thesis too broad, too narrow, or correctly bounded?
2. Is the distinction between competency-controlled evidence and low-canonical
   stress evidence clear?
3. Are the readout mechanism claims convincing without overclaiming model
   improvement?
4. Are the limitations strong enough for a security/ML systems audience?
5. What would be the minimum next step before sharing as a preprint?

## 6. Useful Links

- Paper draft: `paper/draft_v0.md`
- Reviewer checklist: `docs/REVIEWER_CHECKLIST.md`
- Preprint checklist: `docs/PREPRINT_READINESS_CHECKLIST.md`
- Main results: `paper/tables/main_results.md`
- Result anchor map: `paper/result_anchor_map.md`
- References: `paper/references.md`
- External adapter: `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md`
- CI strategy: `docs/CI_TESTING_STRATEGY.md`
