# Reviewer-Readiness Audit

Audits whether `paper/draft_v0.md` is ready to show to an external reviewer,
supervisor, or collaborator. This is an audit only: it does not run experiments,
add claims, or rewrite the paper. It reviewed `paper/draft_v0.md`,
`paper/result_anchor_map.md`, `docs/PAPER_READINESS_AUDIT.md`,
`docs/EXPERIMENT_COMPLETENESS_AUDIT.md`, `reports/RESULTS_INDEX.md`, and the
reports cited by the draft's `[RESULT: ...]` anchors. Each finding below was
checked against the current draft, not recalled.

**Verdict: ready for external review as a working draft, with one substantive
reviewer-facing gap (figures for the new headline sections) and a few optional
polish items. No claim-boundary blocker was found.**

## 1. Claim consistency

A full scan for risk-adjacent language (`solve[d]`, `universal`, `all models`,
`prove[n]/proof`, `generaliz*`, `deploy`, `internal mechanism`, `repair works`)
found **every occurrence inside a disclaimer**, not a bare assertion. The
abstract, introduction, contributions, §6.3 mechanism, §6.4 CrossVul, §8 repair,
and §9 limitations state the same boundaries.

| Risky reading a reviewer might attempt | Status | Where the draft blocks it |
| --- | --- | --- |
| Universal model failure | Handled | §1 "does not prove that all strong secure-code models fail"; §9 "broader than one model but is not a universality claim" |
| Internal mechanism proof | Handled | Abstract "rather than a proven shared internal mechanism"; §6.3, §9 "behavioral, not an internal-mechanistic proof" |
| Learned repair success | Handled | §8 "do not claim that the fine-tuning objective produces a validated learned repair"; Table 4 caveat |
| CrossVul generalization proof | Handled | §6.4 "not… stronger secure-code reasoning by itself"; Table 3 caveat |
| Deployed vulnerability detector | Handled | Abstract "not… a deployed vulnerability detector"; §1; §9 opening |
| Solving secure patch reasoning | Handled | Abstract "We do not claim to solve secure patch reasoning" |

**No sentence requires a claim-boundary edit.** The one wording nuance worth a
deliberate decision (not a defect): the working title *"Pointwise Accuracy Is
Not Relational Reasoning"* uses "reasoning," while the body is careful to claim
*behavioral* evidence, not reasoning. The title reads as a negative claim
(accuracy ≠ reasoning), which is defensible, but a reviewer may still ask
whether "reasoning" overstates the behavioral scope. Recommendation: flag for
the title-finalization decision; no forced change.

## 2. Evidence traceability

Every major result carries a `[RESULT: ...]` anchor, and the draft's anchor set
is verified equal to the anchor set in `paper/result_anchor_map.md` (enforced by
`tests/test_paper_artifacts.py::test_paper_result_anchors_have_report_map`).
Each mapped anchor points to a real report plus supporting JSON, and every
mapped path is checked to exist on disk
(`test_paper_result_anchor_map_artifacts_exist_on_disk`). The new headline
evidence is fully traceable:

| Result | Anchor | Primary report |
| --- | --- | --- |
| Qwen label-only inert | `[RESULT: qwen-label-only-swap]` | `reports/QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` |
| Qwen polarity-only disruptive | `[RESULT: qwen-polarity-only-swap]` | `reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` |
| CodeBERT replication | `[RESULT: codebert-label-polarity-replication]` | `reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md` |
| PrimeVul confound | `[RESULT: polarity-gold-confound]` | `reports/POLARITY_GOLD_CONFOUND.md` |
| CrossVul confound | `[RESULT: crossvul-polarity-gold-confound]` | `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md` |
| Repair decomposition | `[RESULT: antisymmetric-repair]` | `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md` |

Each result sits next to its claim boundary (a caveat sentence or a table
caveat row). **No orphan anchors, no missing artifacts.**

## 3. Table / readability audit

| | Compact? | Caveat visible? | Numbers match reports? | Self-contained? |
| --- | --- | --- | --- | --- |
| Table 2 (§6.3 mechanism) | Yes (5 rows × 2 cols) | Yes ("does not establish a shared internal mechanism") | Verified vs `codebert_label_polarity_mechanism_replication_v1.json` and the Qwen reports | Yes |
| Table 3 (§6.4 confound) | Yes (4 rows × 2 cols) | Yes ("not… standalone evidence of stronger reasoning") | Verified vs `secure_code_polarity_gold_confound_v1.json`, `crossvul_polarity_gold_confound_v1.json` | Yes |
| Table 4 (§8 repair) | Yes (7 rows) | Yes ("antisymmetric consistency is by construction; learned fine-tuning repair is not validated") | Verified vs `secure_code_repair_antisymmetric_decomposition_v1.json` and transfer JSONs | Mostly (defines independent vs antisymmetric inline) |

All three read without the appendix. **Dedicated figures are optional for
correctness but recommended for the new sections** (see §5): the tables are
sufficient to follow the argument, but the paper's *figures* (1–4) currently
depict only the older endpoint/readout story.

## 4. Methodological attack surface

| Reviewer attack | Draft handles it? | Action |
| --- | --- | --- |
| Task is candidate-identity, not directional patch classification | Yes — §3 task boundary + Appendix D prompt contract | No action |
| Polarity may be semantic under a directional task | Yes — §3 states polarity is nuisance *only* under candidate-identity; §9 repeats | No action |
| Behavioral evidence is not internal-mechanism proof | Yes — abstract, §6.3, §9 | No action |
| CodeBERT and Qwen differ in functional form | Yes — stated in main text §6.3 + Table 2, not a footnote | No action |
| CrossVul accuracy is confounded | Yes — §6.4 + Table 3 | No action |
| Human adjudication set is small (20 rows) | Yes — §9 bounds it to diagnostic-scale, excludes AI-pilot round | No action |
| Antisymmetric readout is structural, not learned reasoning | Yes — §8 + Table 4 | No action |
| Fine-tuning repair v1 failed transfer | Yes — §8, Table 4, with p-values | No action |

**All eight anticipated attacks are already addressed in the draft.** None needs
a new main-text edit; the human-adjudication and repair-transfer details are
appropriately in limitations/appendix.

## 5. Submission-readiness checklist

| Item | Classification | Note |
| --- | --- | --- |
| Title finalization | Should fix before external review | Decide on "reasoning" wording (§1 above); low effort |
| Abstract polish | Optional polish | Accurate and bounded; could tighten length |
| Figure completeness | **Should fix before external review** | Figures 1–4 depict the endpoint/readout story; **no figure exists for §6.3 mechanism, §6.4 confound, or §8 repair** — a figure-skimming reviewer would misread the headline |
| Appendix completeness | Done | A–E filled, no placeholders remain |
| Citation completeness | Should fix before external review | Related work uses `[RELATED: ...]` anchors → `references.md`, not a formatted bibliography; adequate for a working draft, not for submission |
| Reproducibility statement | Done | Appendix A + `reproducibility/` manifests + pure-counting scripts |
| Ethics / limitations statement | Done | §9 is thorough; ethics is implicit ("not a deployed scanner") and could be made explicit later |
| Artifact availability statement | Done (working-draft level) | Appendix A / `RESULTS_INDEX.md`; a public-release statement is future work |
| Result-anchor consistency | Done | Enforced by tests |

**Blocker before external review: none.** The two "should fix" items with real
reviewer impact are figure completeness (visual narrative mismatch) and a
citation pass; neither blocks a *working-draft* review, but figures materially
reduce reviewer misreading.

## 6. Recommended next PR

Options considered: (A) reviewer-risk polish pass, (B) add mechanism and repair
figures, (C) finalize title/abstract/contribution wording, (D) external review
packet, (E) no further PR.

**Recommendation: B — `paper: add mechanism and repair figures`.**

Rationale, on reviewer risk rather than aesthetics:
- (A) has little to do: the claim-consistency scan found no bare overclaim to
  polish out; the boundaries were hardened across #56–#62.
- (D) is largely redundant: `docs/EXTERNAL_FEEDBACK_PACKET.md`,
  `docs/REVIEWER_CHECKLIST.md`, and `reports/RESULTS_INDEX.md` already package
  the artifact for external readers.
- (C) addresses only the minor title nuance; better folded into a later pass.
- (B) fixes the single highest reviewer-facing risk found in this audit: the
  paper's figures still tell the pre-#61 endpoint/readout story, so a reviewer
  who skims figures forms the wrong impression of the headline contribution
  (the label-vs-polarity mechanism, the CrossVul confound, and the structural
  repair have no figure). That is a substantive misread risk, not a cosmetic
  one, and Tables 2–4 already give the exact content a figure would visualize.

(E) is not chosen: the figure gap is worth one more PR before external review.
After B, the draft is externally reviewable; C can be a small follow-up.
