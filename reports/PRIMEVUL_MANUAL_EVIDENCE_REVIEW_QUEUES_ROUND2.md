# PrimeVul Manual Evidence Review Queues

These queues are derived from the completed `codex_pilot` audit and are designed for independent follow-up review.

## Queue Files

- High-quality disagreement queue: `data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_round2_v1.jsonl`
- Insufficient-context queue: `data/processed/secure_code_primevul_manual_evidence_insufficient_context_round2_v1.jsonl`

## Review Protocol

- Treat `codex_pilot` as a triage signal, not a final label.
- For high-quality disagreements, decide whether the stored gold side, pilot side, or pair orientation is wrong.
- For insufficient-context cases, inspect wider function/commit context before assigning a vulnerable side.
- Record reviewer identity, final adjudicated side, evidence span, and whether the original hunk window was sufficient.

## High-Quality Disagreement Queue

- Rows: `1`

- priority=`1` `manual_evidence_audit::123::14::FFmpeg__27a99e2c7d450fef15594671eef4465c8a166bd7__CVE-2020-35964`: gold=`A`, pilot=`B`, q=`3`, action=`adjudicate_gold_vs_pilot_direction`

## Insufficient-Context Queue

- Rows: `9`

- priority=`2` `manual_evidence_audit::42::11::linux__d0d62baa7f505bd4c59cd169692ff07ec49dde37__CVE-2021-38205`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`3` `manual_evidence_audit::7::11::mutt__9347b5c01dc52682cb6be11539d9b7ebceae4416__CVE-2018-14349`: gold=`A`, pilot=`unclear`, q=`0`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::12::linux__89c2b3b74918200e46699338d7bcc19b1ea12110__CVE-2022-1508`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::12::minetest__b5956bde259faa240a81060ff4e598e25ad52dae__CVE-2022-24300`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::13::linux__1680939e9ecf7764fba8689cfb3429c2fe2bb23c__CVE-2022-34494`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::13::13::nDPI__8e7b1ea7a136cc4e4aa9880072ec2d69900a825e__CVE-2020-15473`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::13::samba__eb50fb8f3bf670bd7d1cf8fd4368ef4a73083696__CVE-2014-0178`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::99::15::libvirt__524de6cc35d3b222f0e940bb0fd027f5482572c5__CVE-2020-14301`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`3` `manual_evidence_audit::13::15::patch__3fcd042d26d70856e826a42b5f93dc4854d80bf0__CVE-2019-13638`: gold=`B`, pilot=`unclear`, q=`0`, action=`inspect_wider_context_before_direction_label`
