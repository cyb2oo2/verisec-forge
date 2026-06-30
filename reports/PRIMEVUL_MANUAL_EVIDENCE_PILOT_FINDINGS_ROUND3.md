# PrimeVul Manual Evidence Pilot Findings

- Input: `data/processed/secure_code_primevul_manual_evidence_audit_round3_v1.jsonl`
- Completed annotations: `14/14`
- Pilot/gold agreement: `5` match / `9` mismatch
- Agreement rate: `0.3571`
- High-quality disagreements: `0`
- Insufficient-context cases: `9`

Important: this is a `codex_pilot` audit, not independent human gold. It is useful for workflow validation, case triage, and taxonomy design.

## Main Takeaways

- The hard side-inversion queue is not a clean confirmation set: pilot/gold agreement is close to balanced, so many examples need adjudication.
- Strong evidence disagreements are more valuable than weak mismatches because they identify possible label direction conflicts or diff-pair orientation issues.
- `insufficient_context` cases show that hunk/window evidence alone is sometimes too narrow, especially for helper refactors, API semantics, and error-path rewrites.
- The next research step should be independent review of high-quality disagreements plus wider-context review for insufficient-context cases.

## Counts

### Annotators

- `codex_pilot_round3`: `14`

### Evidence Quality

- `0`: `1`
- `1`: `8`
- `2`: `4`
- `3`: `1`

### Label Issues

- `insufficient_context`: `9`
- `none`: `5`

### By Source Pool

- `rank16_20_v1`: match=`5`, mismatch=`9`

## High-Quality Disagreement Queue

- None.

## Insufficient-Context Queue

- `manual_evidence_audit::7::16::hermes__fe52854cdf6725c2eaa9e125995da76e6ceb27da__CVE-2020-1911`: gold=`A`, pilot=`unclear`, q=`0`, note=selfHandle vs propObj variable swap in a HostObject vmcast call; plausible UAF/lifetime relevance but no visible risk/safety signal and direction_unclear labels.
- `manual_evidence_audit::42::16::tensorflow__e952a89b7026b98fe8cbe626514a93ed68b7c510__CVE-2022-23567`: gold=`A`, pilot=`unclear`, q=`1`, note=TensorShape construction reordering; too thin to judge direction without seeing how lhs_dims/lhs_shape are used downstream.
- `manual_evidence_audit::99::17::slurm__07309deb45c33e735e191faf9dd31cca1054a15c__CVE-2020-27746`: gold=`B`, pilot=`unclear`, q=`1`, note=x11_delete_xauth being restructured into x11_set_xauth with add/remove xauth_argv changes; the actual security issue (xauth cookie handling) is not visible in this 2-line preview despite this being flagged as a true inversion candidate.
- `manual_evidence_audit::42::18::tensorflow__4c0ee937c0f61c4fc5f5d32d9bb4c67428012a60__CVE-2021-29584`: gold=`A`, pilot=`unclear`, q=`1`, note=Presence/absence of an overflow-prevention comment alongside SparseTensor::Create reordering; too thin to judge without the surrounding shape-construction logic.
- `manual_evidence_audit::123::19::frr__6d58272b4cf96f0daa846210dd2104877900f921__CVE-2022-37032`: gold=`A`, pilot=`unclear`, q=`1`, note=hdr-struct vs cap-struct bounds-check rewrite with conflicting direction labels across the two windows of the same side (removes_protection+removes_risk on A1, adds_protection+introduces_risk on A2); cannot resolve direction confidently from this preview.
- `manual_evidence_audit::42::19::linux__aa9f7d5172fac9bf1f09e678c35e287a40a7b7dd__CVE-2020-11565`: gold=`A`, pilot=`unclear`, q=`1`, note=Visible change is a comment truncation only (not executable code) in this preview; the risk_support=2 label likely reflects surrounding code not shown here.
- `manual_evidence_audit::99::19::linux__d563131ef23cbc756026f839a82598c8445bc45f__CVE-2019-19071`: gold=`A`, pilot=`unclear`, q=`1`, note=Single dev_kfree_skb(skb) call present on one side, absent on the other; the window's own label (candidate_removes_risk for the side missing the call) reads as the opposite direction from gold A. Flagging rather than asserting given the conflict and lack of surrounding function context.
- `manual_evidence_audit::7::20::MilkyTracker__7afd55c42ad80d01a339197a2d8b5461d214edaf__CVE-2020-15569`: gold=`A`, pilot=`unclear`, q=`1`, note=mixer null-check/delete restructuring; direction_unclear and too thin to judge lifetime safety from this preview.
- `manual_evidence_audit::42::20::openssl__cb22d2ae5a5b6069dbf66dbcce07223ac15a16de__CVE-2015-1793`: gold=`A`, pilot=`unclear`, q=`1`, note=num vs j loop-variable substitution in certificate chain validation (the well-known alternative-chains CVE pattern); near-identical detector probabilities (0.574/0.543) and direction_unclear labels -- not confident enough to assert a side without deeper review of the surrounding loop.
