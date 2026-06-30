# PrimeVul Manual Evidence Pilot Findings

- Input: `data/processed/secure_code_primevul_manual_evidence_audit_round2_v1.jsonl`
- Completed annotations: `19/19`
- Pilot/gold agreement: `9` match / `10` mismatch
- Agreement rate: `0.4737`
- High-quality disagreements: `1`
- Insufficient-context cases: `9`

Important: this is a `codex_pilot` audit, not independent human gold. It is useful for workflow validation, case triage, and taxonomy design.

## Main Takeaways

- The hard side-inversion queue is not a clean confirmation set: pilot/gold agreement is close to balanced, so many examples need adjudication.
- Strong evidence disagreements are more valuable than weak mismatches because they identify possible label direction conflicts or diff-pair orientation issues.
- `insufficient_context` cases show that hunk/window evidence alone is sometimes too narrow, especially for helper refactors, API semantics, and error-path rewrites.
- The next research step should be independent review of high-quality disagreements plus wider-context review for insufficient-context cases.

## Counts

### Annotators

- `codex_pilot_round2`: `19`

### Evidence Quality

- `0`: `2`
- `1`: `8`
- `2`: `7`
- `3`: `2`

### Label Issues

- `insufficient_context`: `9`
- `none`: `10`

### By Source Pool

- `rank11_15_v1`: match=`9`, mismatch=`10`

## High-Quality Disagreement Queue

- `manual_evidence_audit::123::14::FFmpeg__27a99e2c7d450fef15594671eef4465c8a166bd7__CVE-2020-35964`: gold=`A`, pilot=`B`, q=`3`, windows=`A2`, note=Side A's candidate text adds an explicit bounds check ('if (delta > data_len[j]) return AVERROR_INVALIDDATA', direction label candidate_adds_protection, safety_support 5) replacing an av_assert0 that is compiled out in release builds. This reads as side A being the fixed/safer side, contradicting stored gold side A as vulnerable.

## Insufficient-Context Queue

- `manual_evidence_audit::42::11::linux__d0d62baa7f505bd4c59cd169692ff07ec49dde37__CVE-2021-38205`: gold=`B`, pilot=`unclear`, q=`1`, note=Format specifier %p vs %08lX change for a pointer log message; plausible info-leak direction exists but visible windows show no risk/safety support and direction_unclear labels.
- `manual_evidence_audit::7::11::mutt__9347b5c01dc52682cb6be11539d9b7ebceae4416__CVE-2018-14349`: gold=`A`, pilot=`unclear`, q=`0`, note=Single-character pointer offset change (s+2 vs s+3) with near-identical detector probabilities; cannot judge correctness without surrounding buffer-length context.
- `manual_evidence_audit::42::12::linux__89c2b3b74918200e46699338d7bcc19b1ea12110__CVE-2022-1508`: gold=`A`, pilot=`unclear`, q=`1`, note=Single iov_iter_reexpand() call present/absent vs a comment; too little surrounding context to tell whether this is a leak fix or removes needed cleanup.
- `manual_evidence_audit::7::12::minetest__b5956bde259faa240a81060ff4e598e25ad52dae__CVE-2022-24300`: gold=`A`, pilot=`unclear`, q=`1`, note=Metadata::setString()+TOOLCAP_KEY path vs manual clean_name/clean_var+sanitize_string path; cannot tell which validation approach is safer without seeing the called functions.
- `manual_evidence_audit::42::13::linux__1680939e9ecf7764fba8689cfb3429c2fe2bb23c__CVE-2022-34494`: gold=`A`, pilot=`unclear`, q=`1`, note=Explicit kfree(vch) vs a comment claiming it is freed elsewhere; could be a leak fix or a double-free risk depending on the other free path, not visible here.
- `manual_evidence_audit::13::13::nDPI__8e7b1ea7a136cc4e4aa9880072ec2d69900a825e__CVE-2020-15473`: gold=`A`, pilot=`unclear`, q=`1`, note=Packet offset bounds-check line appears in a removed_preview but is labeled candidate_adds_protection; window-label conflict, cannot resolve direction confidently from the 2-line preview.
- `manual_evidence_audit::7::13::samba__eb50fb8f3bf670bd7d1cf8fd4368ef4a73083696__CVE-2014-0178`: gold=`B`, pilot=`unclear`, q=`1`, note=A length-calculation term is added on one side and removed on the other; naive read (smaller computed length implies undersized buffer implies vulnerable) would point to side A, which conflicts with gold B. Flagging rather than asserting either side given the conflict.
- `manual_evidence_audit::99::15::libvirt__524de6cc35d3b222f0e940bb0fd027f5482572c5__CVE-2020-14301`: gold=`A`, pilot=`unclear`, q=`1`, note=Passing xmlformatflags vs a hardcoded 0 to virDomainDiskSourceFormat; cannot judge security relevance without knowing what the flag controls.
- `manual_evidence_audit::13::15::patch__3fcd042d26d70856e826a42b5f93dc4854d80bf0__CVE-2019-13638`: gold=`B`, pilot=`unclear`, q=`0`, note=The sprintf call text is identical in both previews (risk/safety labels differ but the visible 2-line window shows no textual difference); the real change is outside the visible preview.
