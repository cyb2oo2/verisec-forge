# PrimeVul Manual Evidence Review Queues

These queues are derived from the completed `codex_pilot` audit and are designed for independent follow-up review.

## Queue Files

- High-quality disagreement queue: `data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_round3_v1.jsonl`
- Insufficient-context queue: `data/processed/secure_code_primevul_manual_evidence_insufficient_context_round3_v1.jsonl`

## Review Protocol

- Treat `codex_pilot` as a triage signal, not a final label.
- For high-quality disagreements, decide whether the stored gold side, pilot side, or pair orientation is wrong.
- For insufficient-context cases, inspect wider function/commit context before assigning a vulnerable side.
- Record reviewer identity, final adjudicated side, evidence span, and whether the original hunk window was sufficient.

## High-Quality Disagreement Queue

- Rows: `0`


## Insufficient-Context Queue

- Rows: `9`

- priority=`3` `manual_evidence_audit::7::16::hermes__fe52854cdf6725c2eaa9e125995da76e6ceb27da__CVE-2020-1911`: gold=`A`, pilot=`unclear`, q=`0`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::16::tensorflow__e952a89b7026b98fe8cbe626514a93ed68b7c510__CVE-2022-23567`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::99::17::slurm__07309deb45c33e735e191faf9dd31cca1054a15c__CVE-2020-27746`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::18::tensorflow__4c0ee937c0f61c4fc5f5d32d9bb4c67428012a60__CVE-2021-29584`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::123::19::frr__6d58272b4cf96f0daa846210dd2104877900f921__CVE-2022-37032`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::19::linux__aa9f7d5172fac9bf1f09e678c35e287a40a7b7dd__CVE-2020-11565`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::99::19::linux__d563131ef23cbc756026f839a82598c8445bc45f__CVE-2019-19071`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::20::MilkyTracker__7afd55c42ad80d01a339197a2d8b5461d214edaf__CVE-2020-15569`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::20::openssl__cb22d2ae5a5b6069dbf66dbcce07223ac15a16de__CVE-2015-1793`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
