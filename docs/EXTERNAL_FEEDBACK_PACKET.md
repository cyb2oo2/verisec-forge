# External Feedback Packet

This packet is for external reviewers who can spend 5-10 minutes assessing the
research claim, evidence hierarchy, and preprint readiness of VeriSec Forge /
VeriPatch-RR. It is not a new result, benchmark release, or application packet.

## 1. One-Paragraph Summary

VeriSec Forge studies whether secure-code models that appear competent under
pointwise vulnerability detection preserve the vulnerable/fixed relation under
paired patch transformations. The central finding is that pointwise accuracy is
not relational patch understanding: side-order consistency, endpoint
robustness, and runtime visibility must be measured separately. VeriPatch-RR is
a measurement and mechanism study, not a deployed vulnerability scanner.

## 2. Five-Minute Reading Path

1. `README.md`
2. `paper/draft_v0.md` Abstract, Introduction, and Limitations
3. `paper/tables/main_results.md`
4. `paper/result_anchor_map.md`
5. `docs/REVIEWER_CHECKLIST.md`
6. `docs/PREPRINT_READINESS_CHECKLIST.md`

## 3. Claims I Want Feedback On

| Claim | Current Evidence | Feedback Needed |
| --- | --- | --- |
| Pointwise secure-code accuracy is not relational patch understanding. | PrimeVul controls, VeriPatch-RR relation tests, cross-model audit. | Is the claim framed at the right strength? |
| Endpoint robustness is readout-controllable, but side-order reasoning remains unresolved. | Readout ablation, confirmation, frozen-backbone control. | Is the mechanism interpretation convincing? |
| Cross-model stress evidence broadens the failure mode but does not prove universal strong-model failure. | Qwen/CodeBERT audit plus low-canonical distilgpt2/generative slots. | Is this hierarchy clear enough? |

## 4. What This Work Does Not Claim

- It is not a deployed vulnerability scanner.
- It does not solve secure patch reasoning.
- It does not prove all strong models fail.
- It does not promote readout variants as better classifiers.
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
